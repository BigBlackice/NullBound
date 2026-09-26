"""Async subprocess lifecycle, streaming, cancellation, and durable state."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import os
from pathlib import Path
import signal
import subprocess
import time
import re
from typing import Callable, Mapping

from .adapters import AdapterRegistry, ToolAdapter
from .models import (
    CommandSpec,
    CompanionProcessSpec,
    ExecutionError,
    RunEvent,
    RunManifest,
    RunRequest,
    RunState,
    ToolHealth,
    utc_now,
)
from .store import RunStore


RunListener = Callable[[RunEvent], None]
PostRunProcessor = Callable[[RunManifest], Mapping[str, int] | None]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class ExecutionManager:
    """Application-scoped process manager which survives browser reconnects."""

    def __init__(
        self,
        store: RunStore | None = None,
        adapters: AdapterRegistry | None = None,
        max_concurrent: int = 3,
        post_run_processor: PostRunProcessor | None = None,
        progress_interval_seconds: float = 15.0,
    ) -> None:
        self.store = store or RunStore()
        self.adapters = adapters or AdapterRegistry()
        self._limit = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._commands: dict[str, CommandSpec] = {}
        self._run_adapters: dict[str, ToolAdapter] = {}
        self._companion_locks: dict[tuple[str, str, int], asyncio.Lock] = {}
        self._recent_output: dict[str, list[str]] = defaultdict(list)
        self._runs: dict[str, RunManifest] = {}
        self._listeners: dict[str, list[RunListener]] = defaultdict(list)
        self._global_listeners: list[RunListener] = []
        self._cancel_requested: set[str] = set()
        self.post_run_processor = post_run_processor
        self.progress_interval_seconds = progress_interval_seconds

    async def start(self, request: RunRequest, project_path: Path | None = None) -> RunManifest:
        adapter = self.adapters.get(request.module.adapter)
        executable = adapter.resolve_executable(request)
        version = await adapter.version(executable)
        if adapter.version_required and not version:
            raise ExecutionError(
                f"{request.module.bin} did not identify as the expected tool; "
                "check the configured executable path and version"
            )
        run_id, run_path = self.store.reserve(project_path)
        command = adapter.build_command(request, run_path, executable)
        manifest = self.store.create(run_id, run_path, request, command, version)
        self._runs[run_id] = manifest
        self._commands[run_id] = command
        self._run_adapters[run_id] = adapter
        self._tasks[run_id] = asyncio.create_task(self._execute(manifest))
        self._emit(RunEvent(manifest))
        return manifest

    def subscribe(self, run_id: str, listener: RunListener) -> Callable[[], None]:
        self._listeners[run_id].append(listener)
        def unsubscribe() -> None:
            if listener in self._listeners.get(run_id, []):
                self._listeners[run_id].remove(listener)
        return unsubscribe

    def subscribe_all(self, listener: RunListener) -> Callable[[], None]:
        """Observe every run, primarily for project-wide index refreshes."""
        self._global_listeners.append(listener)
        def unsubscribe() -> None:
            if listener in self._global_listeners:
                self._global_listeners.remove(listener)
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

    def unattached_runs(self) -> tuple[RunManifest, ...]:
        return self.store.list_unattached()

    def adopt_unattached(self, project: object) -> tuple[RunManifest, ...]:
        adopted = self.store.adopt_unattached(project)
        for run in adopted:
            pending = self.store.save(run.evolve(evidence_state="pending"))
            self._runs[run.id] = pending
            self._post_process_sync(pending)
        return tuple(self._runs[run.id] for run in adopted)

    def delete_unattached(self) -> tuple[str, ...]:
        removed = self.store.delete_unattached()
        for run_id in removed:
            self._runs.pop(run_id, None)
            self._tasks.pop(run_id, None)
        return removed

    async def check_tool(self, request: RunRequest) -> ToolHealth:
        """Resolve a configured binary and report whether its adapter accepts it."""
        try:
            adapter = self.adapters.get(request.module.adapter)
            executable = adapter.resolve_executable(request)
            version = await adapter.version(executable)
            if adapter.version_required and not version:
                return ToolHealth(
                    "INCOMPATIBLE", executable, None,
                    "Executable was found but did not identify as the expected tool.",
                )
            return ToolHealth("AVAILABLE", executable, version, "Executable is ready.")
        except (ExecutionError, OSError) as error:
            return ToolHealth("MISSING", detail=str(error))

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
                command = self._commands.get(run_id)
                companion_spec = command.companion if command else None
                companion_lock = None
                companion_process = None
                companion_tasks: tuple[asyncio.Task[None], ...] = ()
                if companion_spec is not None:
                    companion_lock = self._companion_locks.setdefault(
                        companion_spec.key, asyncio.Lock()
                    )
                    await companion_lock.acquire()
                try:
                    if companion_spec is not None:
                        companion_process, companion_tasks = await self._start_companion(
                            run_id, manifest, companion_spec, command.environment
                        )
                    self._publish_output(
                        run_id, "system", f"[blackwall] Launching {manifest.module_bin}."
                    )
                    process = await asyncio.create_subprocess_exec(
                        manifest.executable, *manifest.arguments,
                        cwd=manifest.run_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=self._subprocess_environment(command.environment if command else ()),
                        **self._subprocess_options(),
                    )
                    self._processes[run_id] = process
                    manifest = self._transition(manifest, RunState.RUNNING)
                    # Consume stderr first because many CLI tools write their startup
                    # banner there before emitting result records on stdout.
                    async def consume() -> int:
                        await asyncio.gather(
                            self._pump(run_id, process.stderr, "stderr"),
                            self._pump(run_id, process.stdout, "stdout"),
                        )
                        return await process.wait()
                    progress_task = asyncio.create_task(self._report_progress(
                        run_id,
                        manifest,
                        adapter=self._run_adapters.get(run_id),
                        started_clock=started_clock,
                        process=process,
                    ))
                    try:
                        try:
                            if manifest.timeout_seconds:
                                exit_code = await asyncio.wait_for(
                                    consume(), manifest.timeout_seconds
                                )
                            else:
                                exit_code = await consume()
                        finally:
                            progress_task.cancel()
                            await asyncio.gather(progress_task, return_exceptions=True)
                    except TimeoutError:
                        await self._stop_process(process)
                        terminal = self._transition(
                            manifest, RunState.FAILED, exit_code=process.returncode,
                            error=f"run timed out after {manifest.timeout_seconds} seconds",
                            finished_at=utc_now(), duration_seconds=round(time.monotonic() - started_clock, 3),
                            artifacts=self.store.collect_artifacts(manifest.run_path),
                        )
                        self._publish_output(
                            run_id, "system",
                            f"[blackwall] Run timed out after {manifest.timeout_seconds} seconds.",
                        )
                        await self._post_process(terminal)
                        return
                    state = (
                        RunState.CANCELLED if run_id in self._cancel_requested
                        else RunState.COMPLETED if exit_code == 0 else RunState.FAILED
                    )
                    error = None if state in {RunState.COMPLETED, RunState.CANCELLED} else f"process exited with code {exit_code}"
                    terminal = self._transition(
                        manifest, state, exit_code=exit_code, error=error,
                        finished_at=utc_now(), duration_seconds=round(time.monotonic() - started_clock, 3),
                        artifacts=self.store.collect_artifacts(manifest.run_path),
                    )
                    self._publish_output(
                        run_id, "system",
                        f"[blackwall] {state.value.title()} with exit code {exit_code}; "
                        f"collected {len(terminal.artifacts)} artifact(s).",
                    )
                    await self._post_process(terminal)
                finally:
                    if companion_process is not None:
                        await self._stop_process(companion_process)
                        if companion_tasks:
                            await asyncio.gather(*companion_tasks, return_exceptions=True)
                    if companion_lock is not None and companion_lock.locked():
                        companion_lock.release()
        except asyncio.CancelledError:
            terminal = self._transition(
                manifest, RunState.CANCELLED, finished_at=utc_now(),
                artifacts=self.store.collect_artifacts(manifest.run_path),
            )
            self._publish_output(run_id, "system", "[blackwall] Run cancelled.")
            await self._post_process(terminal)
        except Exception as error:
            terminal = self._transition(
                manifest, RunState.FAILED, finished_at=utc_now(), error=str(error),
                artifacts=self.store.collect_artifacts(manifest.run_path),
            )
            self._publish_output(run_id, "system", f"[blackwall] Run failed: {error}")
            await self._post_process(terminal)
        finally:
            self._processes.pop(run_id, None)
            self._commands.pop(run_id, None)
            self._run_adapters.pop(run_id, None)
            self._recent_output.pop(run_id, None)
            self._cancel_requested.discard(run_id)

    async def _start_companion(
        self,
        run_id: str,
        manifest: RunManifest,
        spec: CompanionProcessSpec,
        environment: tuple[tuple[str, str], ...] = (),
    ) -> tuple[asyncio.subprocess.Process | None, tuple[asyncio.Task[None], ...]]:
        """Start a required local service owned and isolated by this run."""
        if await self._endpoint_available(spec):
            raise ExecutionError(
                f"{spec.label} is already running outside this Blackwall run; "
                "stop the existing engine before launching another scan"
            )
        self._publish_output(run_id, "system", f"[blackwall] Starting {spec.label}.")
        process = await asyncio.create_subprocess_exec(
            spec.executable, *spec.arguments,
            cwd=manifest.run_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._subprocess_environment(environment),
            **self._subprocess_options(),
        )
        self._processes[run_id] = process
        tasks = (
            asyncio.create_task(
                self._pump(run_id, process.stderr, "engine_stderr", include_console=False)
            ),
            asyncio.create_task(
                self._pump(run_id, process.stdout, "engine_stdout", include_console=False)
            ),
        )
        deadline = time.monotonic() + spec.startup_timeout_seconds
        try:
            while time.monotonic() < deadline:
                if run_id in self._cancel_requested:
                    raise asyncio.CancelledError
                if process.returncode is not None:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    detail = self._failure_detail(run_id)
                    suffix = f": {detail}" if detail else ""
                    raise ExecutionError(
                        f"{spec.label} exited before becoming ready{suffix}"
                    )
                if await self._endpoint_available(spec):
                    self._publish_output(run_id, "system", f"[blackwall] {spec.label} is ready.")
                    return process, tasks
                await asyncio.sleep(0.2)
            detail = self._failure_detail(run_id)
            suffix = f": {detail}" if detail else ""
            raise ExecutionError(
                f"{spec.label} did not become ready within "
                f"{spec.startup_timeout_seconds:g} seconds{suffix}"
            )
        except BaseException:
            await self._stop_process(process)
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    @staticmethod
    async def _endpoint_available(spec: CompanionProcessSpec) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(spec.ready_host, spec.ready_port), timeout=0.5
            )
        except (OSError, TimeoutError):
            return False
        try:
            if spec.ready_http_path is None:
                return True
            request = (
                f"GET {spec.ready_http_path} HTTP/1.1\r\n"
                f"Host: {spec.ready_host}:{spec.ready_port}\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout=0.5)
            return status_line.startswith(b"HTTP/") and b" 200 " in status_line
        except (OSError, TimeoutError):
            return False
        finally:
            writer.close()
            await writer.wait_closed()

    def _failure_detail(self, run_id: str) -> str:
        lines = self._recent_output.get(run_id, ())
        for line in reversed(lines):
            lowered = line.casefold()
            if "failed" in lowered or "error" in lowered or "panic" in lowered:
                return line[:500]
        return lines[-1][:500] if lines else ""

    @staticmethod
    def _subprocess_options() -> dict[str, object]:
        if os.name == "nt":
            return {
                "creationflags": (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
                )
            }
        return {"start_new_session": True}

    @staticmethod
    def _subprocess_environment(
        overrides: tuple[tuple[str, str], ...],
    ) -> dict[str, str] | None:
        if not overrides:
            return None
        environment = os.environ.copy()
        environment.update(overrides)
        return environment

    async def _stop_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        self._terminate_process(process)
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def _report_progress(
        self,
        run_id: str,
        manifest: RunManifest,
        *,
        adapter: ToolAdapter | None,
        started_clock: float,
        process: asyncio.subprocess.Process,
    ) -> None:
        """Emit throttled progress without relying on terminal redraw output."""
        while process.returncode is None:
            await asyncio.sleep(self.progress_interval_seconds)
            if process.returncode is not None:
                return
            elapsed = max(0, int(time.monotonic() - started_clock))
            minutes, seconds = divmod(elapsed, 60)
            detail = None
            if adapter is not None:
                detail = await asyncio.to_thread(adapter.progress_summary, manifest.run_path)
            suffix = f"; {detail}" if detail else ""
            self._publish_output(
                run_id,
                "system",
                f"[blackwall] {manifest.module_bin} still running — "
                f"{minutes:02d}:{seconds:02d} elapsed{suffix}.",
            )

    async def _pump(
        self,
        run_id: str,
        stream: asyncio.StreamReader | None,
        stream_name: str,
        *,
        include_console: bool = True,
    ) -> None:
        if stream is None:
            return
        manifest = self._runs[run_id]
        log_path = manifest.run_path / f"{stream_name}.log"
        console_log = (
            (manifest.run_path / "console.log").open("a", encoding="utf-8", errors="replace")
            if include_console else None
        )
        try:
            with log_path.open("a", encoding="utf-8", errors="replace") as log:
                while line := await stream.readline():
                    text = line.decode(errors="replace").rstrip("\r\n")
                    text = ANSI_ESCAPE.sub("", text)
                    recent = self._recent_output[run_id]
                    recent.append(text)
                    del recent[:-20]
                    log.write(text + "\n")
                    log.flush()
                    if console_log is not None:
                        console_log.write(text + "\n")
                        console_log.flush()
                        self._emit(RunEvent(self._runs[run_id], stream_name, text))
        finally:
            if console_log is not None:
                console_log.close()

    def _publish_output(self, run_id: str, stream_name: str, text: str) -> None:
        """Persist a concise Blackwall lifecycle message and emit it live."""
        manifest = self._runs[run_id]
        for path in (
            manifest.run_path / f"{stream_name}.log",
            manifest.run_path / "console.log",
        ):
            with path.open("a", encoding="utf-8", errors="replace") as output:
                output.write(text + "\n")
        self._emit(RunEvent(manifest, stream_name, text))

    def _transition(self, manifest: RunManifest, state: RunState, **changes: object) -> RunManifest:
        current = self._runs.get(manifest.id, manifest)
        updated = self.store.save(current.evolve(state=state, **changes))
        self._runs[manifest.id] = updated
        self._emit(RunEvent(updated))
        return updated

    def _emit(self, event: RunEvent) -> None:
        listeners = (
            *tuple(self._listeners.get(event.run.id, ())),
            *tuple(self._global_listeners),
        )
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                if listener in self._listeners.get(event.run.id, []):
                    self._listeners[event.run.id].remove(listener)
                if listener in self._global_listeners:
                    self._global_listeners.remove(listener)

    async def _post_process(self, manifest: RunManifest) -> None:
        if manifest.project_id is None or self.post_run_processor is None:
            return
        try:
            indexing = self._transition(
                manifest, manifest.state, evidence_state="indexing",
                evidence_parser=manifest.module_bin.casefold(), evidence_error=None,
            )
            summary = await asyncio.to_thread(self.post_run_processor, indexing)
            self._transition(
                indexing, indexing.state,
                evidence_state="indexed" if summary is not None else "no_artifact",
                evidence_summary=tuple(sorted((summary or {}).items())),
            )
        except Exception as error:
            current = self._runs.get(manifest.id, manifest)
            try:
                self._transition(
                    current, current.state, evidence_state="failed", evidence_error=str(error),
                )
            except Exception:
                pass

    def _post_process_sync(self, manifest: RunManifest) -> None:
        """Index an adopted terminal run from synchronous project creation code."""
        if manifest.project_id is None or self.post_run_processor is None:
            return
        try:
            indexing = self._transition(
                manifest, manifest.state, evidence_state="indexing",
                evidence_parser=manifest.module_bin.casefold(), evidence_error=None,
            )
            summary = self.post_run_processor(indexing)
            self._transition(
                indexing, indexing.state,
                evidence_state="indexed" if summary is not None else "no_artifact",
                evidence_summary=tuple(sorted((summary or {}).items())),
            )
        except Exception as error:
            current = self._runs.get(manifest.id, manifest)
            try:
                self._transition(
                    current, current.state, evidence_state="failed", evidence_error=str(error),
                )
            except Exception:
                pass

    @staticmethod
    def _terminate_process(process: asyncio.subprocess.Process) -> None:
        try:
            if os.name != "nt" and process.pid:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
