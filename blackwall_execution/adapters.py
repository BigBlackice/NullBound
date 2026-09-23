"""Safe argv-based adapter contract and the first httpx implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from pathlib import Path
import shutil

from .models import CommandSpec, ExecutionError, RunRequest


def expand_argument_template(
    template: tuple[str, ...], targets: tuple[str, ...]
) -> tuple[str, ...]:
    """Expand typed targets while preserving argv element boundaries."""
    if "{target}" not in template:
        if targets:
            raise ExecutionError("profile argument template has no {target} placeholder")
        return template
    if template.count("{target}") != 1:
        raise ExecutionError("profile argument template must contain one {target} placeholder")
    index = template.index("{target}")
    repeated_prefix = (template[index - 1],) if index else ()
    prefix = template[: index - 1] if index else ()
    suffix = template[index + 1 :]
    expanded = [*prefix]
    for target in targets:
        expanded.extend((*repeated_prefix, target))
    expanded.extend(suffix)
    return tuple(expanded)


class ToolAdapter(ABC):
    """Small interface implemented by built-in and future plugin adapters."""

    key = "declarative"
    version_required = False

    def resolve_executable(self, request: RunRequest) -> str:
        configured = request.module.path
        has_path = Path(configured).is_absolute() or any(x in configured for x in ("/", "\\"))
        if has_path:
            path = Path(configured).expanduser().resolve(strict=False)
            if not path.is_file():
                raise ExecutionError(f"executable does not exist: {path}")
            return str(path)
        resolved = shutil.which(configured)
        if not resolved:
            raise ExecutionError(f"{request.module.bin} is unavailable; configure its executable path")
        return resolved

    async def version(self, executable: str) -> str | None:
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                executable, self.version_argument(),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            if process and process.returncode is None:
                process.kill()
                await process.communicate()
            return None
        except OSError:
            return None
        if process.returncode != 0:
            return None
        text = (stdout or stderr).decode(errors="replace").strip().splitlines()
        return text[0][:240] if text else None

    def version_argument(self) -> str:
        return "-version"

    @abstractmethod
    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        raise NotImplementedError


class DeclarativeAdapter(ToolAdapter):
    """Execute catalog profiles without evaluating a shell command string."""

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        template = request.profile.arguments
        if not template:
            raise ExecutionError(f"profile {request.profile.name!r} has no executable argument template")
        arguments = expand_argument_template(
            template, tuple(x.normalized for x in request.context.selection.targets)
        )
        return CommandSpec(executable, arguments, request.profile.output_format)


class HttpxAdapter(DeclarativeAdapter):
    key = "httpx"
    version_required = True

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "httpx.jsonl"
        return CommandSpec(
            executable=command.executable,
            arguments=(*command.arguments, "-o", str(artifact)),
            output_format="jsonl",
        )


class AdapterRegistry:
    """Resolve adapters by catalog key so runtime modules stay data-driven."""

    def __init__(self, adapters: tuple[ToolAdapter, ...] | None = None) -> None:
        installed = adapters or (DeclarativeAdapter(), HttpxAdapter())
        self._adapters = {adapter.key: adapter for adapter in installed}

    def get(self, key: str) -> ToolAdapter:
        try:
            return self._adapters[key]
        except KeyError as error:
            raise ExecutionError(f"unknown module adapter: {key}") from error
