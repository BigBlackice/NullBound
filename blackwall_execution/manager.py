"""Async subprocess lifecycle, streaming, cancellation, and durable state."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import os
from pathlib import Path
import signal
import time
import re
from typing import Callable

from .adapters import AdapterRegistry
from .models import RunEvent, RunManifest, RunRequest, RunState, utc_now
from .store import RunStore


RunListener = Callable[[RunEvent], None]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class ExecutionManager:
    """Application-scoped process manager which survives browser reconnects."""

    def __init__(
        self,
        store: RunStore | None = None,
        adapters: AdapterRegistry | None = None,
        max_concurrent: int = 3,
    ) -> None:
        self.store = store or RunStore()
        self.adapters = adapters or AdapterRegistry()
        self._limit = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._runs: dict[str, RunManifest] = {}
        self._listeners: dict[str, list[RunListener]] = defaultdict(list)
        self._cancel_requested: set[str] = set()

    async def start(self, request: RunRequest, project_path: Path | None = None) -> RunManifest:
        adapter = self.adapters.get(request.module.adapter)
        executable = adapter.resolve_executable(request)
        version = await adapter.version(executable)
        if adapter.version_required and not version:
            raise ExecutionError(
                f"{request.module.bin} did not identify as the expected tool; "
                "configure the ProjectDiscovery httpx executable"
            )
        run_id, run_path = self.store.reserve(project_path)
        command = adapter.build_command(request, run_path, executable)
        manifest = self.store.create(run_id, run_path, request, command, version)
        self._runs[run_id] = manifest
        self._tasks[run_id] = asyncio.create_task(self._execute(manifest))
        self._emit(RunEvent(manifest))
        return manifest

    def subscribe(self, run_id: str, listener: RunListener) -> Callable[[], None]:
        self._listeners[run_id].append(listener)
        def unsubscribe() -> None:
            if listener in self._listeners.get(run_id, []):
                self._listeners[run_id].remove(listener)
        return unsubscribe

    async def cancel(self, run_id: str) -> bool:
        manifest = self._runs.get(run_id)
        if manifest is None or manifest.state.terminal:
            return False
        self._cancel_requested.add(run_id)
        process = self._processes.get(run_id)
        if process is not None and process.returncode is None:
            self._terminate_process(process)
        task = self._tasks.get(run_id)
        if task is not None and process is None:
            self._transition(manifest, RunState.CANCELLED, finished_at=utc_now())
            task.cancel()
        return True

    def get(self, run_id: str) -> RunManifest:
        return self._runs[run_id]

    def list_runs(self, project_paths: tuple[Path, ...] = ()) -> tuple[RunManifest, ...]:
        persisted = {run.id: run for run in self.store.list_runs(project_paths)}
        persisted.update(self._runs)
        return tuple(sorted(persisted.values(), key=lambda item: item.created_at, reverse=True))

    def recover_incomplete(self, project_paths: tuple[Path, ...] = ()) -> tuple[RunManifest, ...]:
        """Fail stale persisted runs without touching processes owned by this manager."""
        recovered: list[RunManifest] = []
        for manifest in self.store.list_runs(project_paths):
            if manifest.state.terminal or manifest.id in self._runs:
                continue
            recovered.append(self.store.save(manifest.evolve(
                state=RunState.FAILED,
                finished_at=utc_now(),
                error="Blackwall stopped before the run completed",
            )))
        return tuple(recovered)

    async def wait(self, run_id: str) -> RunManifest:
        task = self._tasks.get(run_id)
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass
        return self._runs[run_id]

    async def _execute(self, manifest: RunManifest) -> None:
        run_id = manifest.id
        try:
            async with self._limit:
                if run_id in self._cancel_requested:
                    raise asyncio.CancelledError
                started_clock = time.monotonic()
                manifest = self._transition(manifest, RunState.STARTING, started_at=utc_now())
                kwargs: dict[str, object] = {}
                if os.name == "nt":
                    kwargs["creationflags"] = 0x00000200  # CREATE_NEW_PROCESS_GROUP
                else:
                    kwargs["start_new_session"] = True
                process = await asyncio.create_subprocess_exec(
                    manifest.executable, *manifest.arguments,
                    cwd=manifest.run_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    **kwargs,
                )
                self._processes[run_id] = process
                manifest = self._transition(manifest, RunState.RUNNING)
                # Consume stderr first because many CLI tools write their startup
                # banner there before emitting result records on stdout.
                await asyncio.gather(
                    self._pump(run_id, process.stderr, "stderr"),
                    self._pump(run_id, process.stdout, "stdout"),
                )
                exit_code = await process.wait()
                state = (
                    RunState.CANCELLED if run_id in self._cancel_requested
                    else RunState.COMPLETED if exit_code == 0 else RunState.FAILED
                )
                error = None if state in {RunState.COMPLETED, RunState.CANCELLED} else f"process exited with code {exit_code}"
                self._transition(
                    manifest, state, exit_code=exit_code, error=error,
                    finished_at=utc_now(), duration_seconds=round(time.monotonic() - started_clock, 3),
                    artifacts=self.store.collect_artifacts(manifest.run_path),
                )
        except asyncio.CancelledError:
            self._transition(manifest, RunState.CANCELLED, finished_at=utc_now())
        except Exception as error:
            self._transition(manifest, RunState.FAILED, finished_at=utc_now(), error=str(error))
        finally:
            self._processes.pop(run_id, None)
            self._cancel_requested.discard(run_id)

    async def _pump(
        self,
        run_id: str,
        stream: asyncio.StreamReader | None,
        stream_name: str,
    ) -> None:
        if stream is None:
            return
        manifest = self._runs[run_id]
        log_path = manifest.run_path / f"{stream_name}.log"
        console_path = manifest.run_path / "console.log"
        with (
            log_path.open("a", encoding="utf-8", errors="replace") as log,
            console_path.open("a", encoding="utf-8", errors="replace") as console_log,
        ):
            while line := await stream.readline():
                text = line.decode(errors="replace").rstrip("\r\n")
                text = ANSI_ESCAPE.sub("", text)
                log.write(text + "\n")
                log.flush()
                console_log.write(text + "\n")
                console_log.flush()
                self._emit(RunEvent(self._runs[run_id], stream_name, text))

    def _transition(self, manifest: RunManifest, state: RunState, **changes: object) -> RunManifest:
        current = self._runs.get(manifest.id, manifest)
        updated = self.store.save(current.evolve(state=state, **changes))
        self._runs[manifest.id] = updated
        self._emit(RunEvent(updated))
        return updated

    def _emit(self, event: RunEvent) -> None:
        for listener in tuple(self._listeners.get(event.run.id, ())):
            try:
                listener(event)
            except Exception:
                self._listeners[event.run.id].remove(listener)

    @staticmethod
    def _terminate_process(process: asyncio.subprocess.Process) -> None:
        try:
            if os.name != "nt" and process.pid:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
