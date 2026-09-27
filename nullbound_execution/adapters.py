"""Safe argv-based adapter contract and built-in CLI implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory

from .models import CommandSpec, ExecutionError, RunRequest


def expand_argument_template(
    template: tuple[str, ...],
    targets: tuple[str, ...],
    *,
    target_file: str | None = None,
) -> tuple[str, ...]:
    """Expand target tokens while preserving argv element boundaries.

    ``{target}`` repeats its preceding option for every target, ``{targets}``
    inserts positional targets, and ``{target_file}`` inserts a generated list.
    """
    tokens = {token for token in ("{target}", "{targets}", "{target_file}") if token in template}
    if not tokens:
        if targets:
            raise ExecutionError("profile argument template has no target placeholder")
        return template
    if len(tokens) != 1:
        raise ExecutionError("profile must use exactly one target placeholder style")

    token = tokens.pop()
    if template.count(token) != 1:
        raise ExecutionError(f"profile argument template must contain one {token} placeholder")
    index = template.index(token)
    if token == "{targets}":
        return (*template[:index], *targets, *template[index + 1 :])
    if token == "{target_file}":
        if target_file is None:
            raise ExecutionError("profile requires a generated target file")
        return (*template[:index], target_file, *template[index + 1 :])

    repeated_prefix = (template[index - 1],) if index else ()
    prefix = template[: index - 1] if index else ()
    suffix = template[index + 1 :]
    return (
        *prefix,
        *(item for target in targets for item in (*repeated_prefix, target)),
        *suffix,
    )


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
            if not os.access(path, os.X_OK):
                raise ExecutionError(f"executable is not runnable: {path}")
            return str(path)
        resolved = shutil.which(configured)
        if not resolved:
            raise ExecutionError(f"{request.module.bin} is unavailable; configure its executable path")
        return resolved

    async def version(self, executable: str) -> str | None:
        process: asyncio.subprocess.Process | None = None
        try:
            kwargs: dict[str, object] = {}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            process = await asyncio.create_subprocess_exec(
                executable, *self.version_arguments(),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                **kwargs,
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
        lines = (stdout + b"\n" + stderr).decode(errors="replace").strip().splitlines()
        return self.parse_version(lines)

    def version_arguments(self) -> tuple[str, ...]:
        return ("-version",)

    def parse_version(self, lines: list[str]) -> str | None:
        return lines[0][:240] if lines else None

    def progress_summary(self, run_path: Path) -> str | None:
        """Return a concise live summary for long-running tools, when available."""
        return None

    @abstractmethod
    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        raise NotImplementedError

    def preview_command(self, request: RunRequest, executable: str) -> CommandSpec:
        """Build a display command. Adapters may override to avoid side effects."""
        return self.build_command(request, Path("<run>"), executable)


class DeclarativeAdapter(ToolAdapter):
    """Execute catalog profiles without evaluating a shell command string."""

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        template = request.profile.arguments
        if not template:
            raise ExecutionError(f"profile {request.profile.name!r} has no executable argument template")
        targets = tuple(x.normalized for x in request.context.selection.targets)
        target_file = None
        if "{target_file}" in template:
            input_path = run_path / "inputs" / "targets.txt"
            input_path.parent.mkdir(parents=True, exist_ok=True)
            input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
            target_file = str(input_path)
        arguments = expand_argument_template(template, targets, target_file=target_file)
        arguments = (*arguments, *self._option_arguments(request))
        return CommandSpec(executable, arguments, request.profile.output_format)

    def preview_command(self, request: RunRequest, executable: str) -> CommandSpec:
        """Use the real builder, replacing its disposable run directory in the result."""
        with TemporaryDirectory(prefix="nullbound-preview-") as temporary:
            root = Path(temporary)
            command = self.build_command(request, root, executable)
            root_text = str(root)
            arguments = tuple(
                argument.replace(root_text, "<run>") for argument in command.arguments
            )
            environment = tuple(
                (key, value.replace(root_text, "<run>"))
                for key, value in command.environment
            )
            return CommandSpec(
                command.executable, arguments, command.output_format,
                environment=environment,
            )

    @staticmethod
    def _option_arguments(request: RunRequest) -> tuple[str, ...]:
        fields = {field.id: field for field in request.module.config_fields}
        arguments: list[str] = []
        for key, raw_value in request.options:
            if key not in fields:
                raise ExecutionError(f"unknown configuration field for module: {key}")
            value = raw_value.strip()
            if not value:
                continue
            if any(ord(character) < 32 for character in value):
                raise ExecutionError(f"module option {key} contains control characters")
            arguments.extend((fields[key].argument, value))
        return tuple(arguments)


class HttpxAdapter(DeclarativeAdapter):
    key = "httpx"
    version_required = True

    def version_arguments(self) -> tuple[str, ...]:
        return ("-version", "-no-color")

    def parse_version(self, lines: list[str]) -> str | None:
        for line in lines:
            match = re.search(r"current(?: httpx)? version:?\s+(v?[^\s(]+)", line, re.IGNORECASE)
            if match:
                return match.group(1)[:240]
        return None

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "httpx.jsonl"
        return CommandSpec(
            executable=command.executable,
            arguments=(*command.arguments, "-no-color", "-o", str(artifact)),
            output_format="jsonl",
        )


class ProjectDiscoveryAdapter(DeclarativeAdapter):
    """Shared version parsing for ProjectDiscovery command-line tools."""

    version_required = True

    def version_arguments(self) -> tuple[str, ...]:
        return ("-version", "-no-color")

    def parse_version(self, lines: list[str]) -> str | None:
        for line in lines:
            match = re.search(
                r"(?:current\s+)?(?:[a-z0-9_-]+\s+)?version:?\s+(v?[0-9][^\s(]*)",
                line,
                re.IGNORECASE,
            )
            if match:
                return match.group(1)[:240]
        return None


class ArtifactAdapter(DeclarativeAdapter):
    """Declarative command with a tool-specific machine-readable artifact."""

    artifact_name = "output.txt"
    artifact_arguments: tuple[str, ...] = ()
    artifact_format = "text"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / self.artifact_name
        arguments = tuple(str(artifact) if item == "{artifact}" else item for item in self.artifact_arguments)
        return CommandSpec(command.executable, (*command.arguments, *arguments), self.artifact_format)


class SubfinderAdapter(ProjectDiscoveryAdapter):
    """Emit compact source-attributed JSONL without maintaining a private database."""

    key = "subfinder"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "subfinder.jsonl"
        return CommandSpec(
            command.executable,
            (
                *command.arguments,
                "-json", "-collect-sources", "-silent", "-no-color",
                "-disable-update-check", "-o", str(artifact),
            ),
            "jsonl",
        )


class DnsxAdapter(ProjectDiscoveryAdapter):
    key = "dnsx"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "dnsx.jsonl"
        return CommandSpec(command.executable, (*command.arguments, "-json", "-no-color", "-o", str(artifact)), "jsonl")


class NmapAdapter(ArtifactAdapter):
    key = "nmap"
    artifact_name = "nmap.xml"
    artifact_arguments = ("-oX", "{artifact}")
    artifact_format = "xml"

    def version_arguments(self) -> tuple[str, ...]:
        return ("--version",)


class GauAdapter(ArtifactAdapter):
    key = "gau"
    artifact_name = "gau.jsonl"
    artifact_arguments = ("--json", "--o", "{artifact}")
    artifact_format = "jsonl"

    def version_arguments(self) -> tuple[str, ...]:
        return ("--version",)


class TlsxAdapter(ProjectDiscoveryAdapter):
    key = "tlsx"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "tlsx.jsonl"
        return CommandSpec(command.executable, (*command.arguments, "-json", "-no-color", "-o", str(artifact)), "jsonl")


class AdapterRegistry:
    """Resolve adapters by catalog key so runtime modules stay data-driven."""

    def __init__(self, adapters: tuple[ToolAdapter, ...] | None = None) -> None:
        installed = adapters or (
            DeclarativeAdapter(), SubfinderAdapter(), DnsxAdapter(), NmapAdapter(),
            HttpxAdapter(), GauAdapter(), TlsxAdapter(),
        )
        self._adapters = {adapter.key: adapter for adapter in installed}

    def get(self, key: str) -> ToolAdapter:
        try:
            return self._adapters[key]
        except KeyError as error:
            raise ExecutionError(f"unknown module adapter: {key}") from error
