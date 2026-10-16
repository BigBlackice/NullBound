"""Safe argv-based adapter contract and built-in CLI implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit, urlunsplit

from nullbound_scope import TargetKind

from .models import CommandSpec, ExecutionError, ProxyConfig, RunRequest


SECLISTS_WEB_CONTENT_ROOT = Path("/usr/share/seclists/Discovery/Web-Content")
SECLISTS_PASSWORD_ROOT = Path("/usr/share/seclists/Passwords")
DEFAULT_FFUF_WORDLIST = "raft-medium-directories.txt"
DEFAULT_PASSWORD_WORDLIST = "10-million-password-list-top-10000.txt"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TOOLS_ROOT = PROJECT_ROOT / ".nullbound-tools"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _which_outside_local_tools(command: str) -> str | None:
    path_entries = (
        entry.strip('"')
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    )
    system_path = os.pathsep.join(
        entry for entry in path_entries
        if not _is_within(Path(entry), LOCAL_TOOLS_ROOT)
    )
    return shutil.which(command, path=system_path)


def _discover_wordlists(
    root: Path,
    *,
    pattern: str,
    preferred_name: str,
) -> tuple[Path, ...]:
    try:
        if not root.is_dir():
            return ()
        wordlists = tuple(path for path in root.rglob(pattern) if path.is_file())
    except OSError:
        return ()
    return tuple(sorted(
        wordlists,
        key=lambda path: (
            path.name.casefold() != preferred_name.casefold(),
            path.relative_to(root).as_posix().casefold(),
        ),
    ))


def discover_ffuf_wordlists(
    root: Path = SECLISTS_WEB_CONTENT_ROOT,
    *,
    all_files: bool = False,
) -> tuple[Path, ...]:
    """Return readable FFUF wordlist candidates with the preferred list first."""
    return _discover_wordlists(
        root,
        pattern="*" if all_files else "*.txt",
        preferred_name=DEFAULT_FFUF_WORDLIST,
    )


def discover_password_wordlists(
    root: Path = SECLISTS_PASSWORD_ROOT,
    *,
    all_files: bool = False,
) -> tuple[Path, ...]:
    return _discover_wordlists(
        root,
        pattern="*" if all_files else "*.txt",
        preferred_name=DEFAULT_PASSWORD_WORDLIST,
    )


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
    proxy_protocols: tuple[str, ...] = ()
    proxy_argument = ""

    def resolve_executable(self, request: RunRequest) -> str:
        configured = request.module.path
        has_path = Path(configured).is_absolute() or any(x in configured for x in ("/", "\\"))
        if has_path:
            path = Path(configured).expanduser().resolve(strict=False)
            if _is_within(path, LOCAL_TOOLS_ROOT):
                system_executable = _which_outside_local_tools(request.module.bin)
                if system_executable:
                    return system_executable
            if not path.is_file():
                raise ExecutionError(f"executable does not exist: {path}")
            if not os.access(path, os.X_OK):
                raise ExecutionError(f"executable is not runnable: {path}")
            return str(path)
        resolved = _which_outside_local_tools(configured) or shutil.which(configured)
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

    async def identify(self, request: RunRequest, executable: str) -> str | None:
        return await self.version(executable)

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

    def validate_proxy(self, request: RunRequest) -> None:
        if request.proxy is not None and request.proxy.protocol not in self.proxy_protocols:
            supported = ", ".join(item.upper() for item in self.proxy_protocols) or "none"
            raise ExecutionError(
                f"{request.module.bin} cannot honor the enabled "
                f"{request.proxy.protocol.upper()} proxy; supported: {supported}"
            )

    def route_proxy(self, request: RunRequest, command: CommandSpec) -> CommandSpec:
        """Apply or explicitly disable proxy routing for one prepared command."""
        self.validate_proxy(request)
        arguments = command.arguments
        if request.proxy is not None:
            if not self.proxy_argument:
                raise ExecutionError(f"{request.module.bin} has no proxy argument")
            if self.proxy_argument in arguments:
                raise ExecutionError(
                    f"{request.module.bin} profile already contains {self.proxy_argument}; "
                    "remove the per-profile proxy setting"
                )
            arguments = (*arguments, self.proxy_argument, request.proxy.url)
        environment = (*command.environment, *self._proxy_environment(request.proxy))
        return CommandSpec(
            command.executable,
            arguments,
            command.output_format,
            command.companion,
            environment,
        )

    @staticmethod
    def _proxy_environment(proxy: ProxyConfig | None) -> tuple[tuple[str, str], ...]:
        names = (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
        )
        if proxy is None:
            return (*((name, "") for name in names), ("NO_PROXY", "*"), ("no_proxy", "*"))
        pairs: list[tuple[str, str]] = [(name, proxy.url) for name in names]
        pairs.extend((("NO_PROXY", ""), ("no_proxy", "")))
        if proxy.ca_certificate:
            certificate = str(Path(proxy.ca_certificate).expanduser().resolve())
            pairs.extend((("SSL_CERT_FILE", certificate), ("REQUESTS_CA_BUNDLE", certificate)))
        return tuple(pairs)


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
    proxy_protocols = ("http", "socks5")
    proxy_argument = "-proxy"

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
    proxy_protocols = ("http",)
    proxy_argument = "-proxy"

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
    proxy_protocols = ("http", "socks5")
    proxy_argument = "--proxy"

    def version_arguments(self) -> tuple[str, ...]:
        return ("--version",)


class FfufAdapter(ArtifactAdapter):
    key = "ffuf"
    version_required = True
    artifact_name = "ffuf.json"
    artifact_arguments = ("-noninteractive", "-of", "json", "-o", "{artifact}")
    artifact_format = "json"
    proxy_protocols = ("http", "socks5")
    proxy_argument = "-x"

    def version_arguments(self) -> tuple[str, ...]:
        return ("-V",)

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        targets = request.context.selection.targets
        if len(targets) != 1 or targets[0].kind is not TargetKind.URL:
            raise ExecutionError("ffuf directory discovery requires exactly one HTTP/S URL")
        options = dict(request.options)
        wordlist_text = options.get("wordlist", "").strip()
        if not wordlist_text:
            raise ExecutionError("ffuf directory discovery requires a wordlist")
        wordlist = Path(wordlist_text).expanduser().resolve()
        if not wordlist.is_file():
            raise ExecutionError(f"ffuf wordlist does not exist: {wordlist}")
        if depth_text := options.get("recursion_depth", "").strip():
            try:
                depth = int(depth_text)
            except ValueError as error:
                raise ExecutionError("ffuf recursion depth must be a whole number from 1 to 10") from error
            if not 1 <= depth <= 10:
                raise ExecutionError("ffuf recursion depth must be a whole number from 1 to 10")

        command = super().build_command(request, run_path, executable)
        arguments = list(command.arguments)
        url_index = arguments.index("-u") + 1
        parsed = urlsplit(targets[0].normalized)
        arguments[url_index] = urlunsplit((
            parsed.scheme, parsed.netloc, f"{parsed.path.rstrip('/')}/FUZZ", "", "",
        ))
        wordlist_index = arguments.index("-w") + 1
        arguments[wordlist_index] = str(wordlist)
        return CommandSpec(command.executable, tuple(arguments), command.output_format)


class TlsxAdapter(ProjectDiscoveryAdapter):
    key = "tlsx"
    proxy_protocols = ("socks5",)
    proxy_argument = "-proxy"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        command = super().build_command(request, run_path, executable)
        artifact = run_path / "artifacts" / "tlsx.jsonl"
        return CommandSpec(command.executable, (*command.arguments, "-json", "-no-color", "-o", str(artifact)), "jsonl")


class NucleiAdapter(ArtifactAdapter):
    key = "nuclei"
    version_required = True
    artifact_name = "nuclei.jsonl"
    artifact_arguments = ("-silent", "-nc", "-jle", "{artifact}")
    artifact_format = "jsonl"
    proxy_protocols = ("http", "socks5")
    proxy_argument = "-proxy"

    def version_arguments(self) -> tuple[str, ...]:
        return ("-version", "-no-color")

    def parse_version(self, lines: list[str]) -> str | None:
        for line in lines:
            match = re.search(r"nuclei\s+version:?\s+(v?[^\s(]+)", line, re.IGNORECASE)
            if match:
                return match.group(1)[:240]
        return None


class PythonScriptAdapter(DeclarativeAdapter):
    """Run a checked Python tool script with NullBound's current interpreter."""

    version_required = True
    version_flags: tuple[str, ...] = ("--version",)

    def script_path(self, request: RunRequest) -> Path:
        configured = Path(request.module.path).expanduser()
        candidates = [configured]
        if not configured.is_absolute():
            project_root = Path(__file__).resolve().parents[1]
            candidates.append(project_root / configured)
        for candidate in candidates:
            resolved = candidate.resolve(strict=False)
            if resolved.is_file():
                return resolved
        raise ExecutionError(
            f"{request.module.bin} script is unavailable; configure its script path"
        )

    def resolve_executable(self, request: RunRequest) -> str:
        self.script_path(request)
        return sys.executable

    async def identify(self, request: RunRequest, executable: str) -> str | None:
        process: asyncio.subprocess.Process | None = None
        try:
            kwargs: dict[str, object] = {}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            process = await asyncio.create_subprocess_exec(
                executable, str(self.script_path(request)), *self.version_flags,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                **kwargs,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except (OSError, TimeoutError):
            if process and process.returncode is None:
                process.kill()
                await process.communicate()
            return None
        if process.returncode != 0:
            return None
        lines = (stdout + b"\n" + stderr).decode(errors="replace").strip().splitlines()
        return self.parse_version(lines)


class SqlmapAdapter(PythonScriptAdapter):
    key = "sqlmap"
    proxy_protocols = ("http",)
    proxy_argument = "--proxy"

    def resolve_executable(self, request: RunRequest) -> str:
        return _which_outside_local_tools(request.module.bin) or super().resolve_executable(request)

    def version_arguments(self) -> tuple[str, ...]:
        return self.version_flags

    async def identify(self, request: RunRequest, executable: str) -> str | None:
        if Path(executable).resolve(strict=False) != Path(sys.executable).resolve(strict=False):
            return await self.version(executable)
        return await super().identify(request, executable)

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        targets = request.context.selection.targets
        if len(targets) != 1 or targets[0].kind is not TargetKind.URL:
            raise ExecutionError("sqlmap requires exactly one HTTP/S URL")
        arguments = expand_argument_template(
            request.profile.arguments, (targets[0].normalized,)
        )
        arguments = (*arguments, *self._option_arguments(request))
        output = run_path / "artifacts" / "sqlmap"
        script = (
            (str(self.script_path(request)),)
            if Path(executable).resolve(strict=False) == Path(sys.executable).resolve(strict=False)
            else ()
        )
        return CommandSpec(
            executable,
            (*script, *arguments, "--output-dir", str(output)),
            "text",
        )


class BrutepywebAdapter(PythonScriptAdapter):
    key = "brutepyweb"
    version_flags = ("-h",)
    proxy_protocols = ("http", "socks5")

    def parse_version(self, lines: list[str]) -> str | None:
        return (
            "brutepyweb"
            if any("password-file" in line.casefold() for line in lines)
            else None
        )

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        targets = request.context.selection.targets
        if len(targets) != 1 or targets[0].kind is not TargetKind.URL:
            raise ExecutionError("brutepyweb requires exactly one HTTP/S login URL")
        options = dict(request.options)
        password_file = Path(options.get("password_file", "")).expanduser().resolve()
        if not password_file.is_file():
            raise ExecutionError(f"password wordlist does not exist: {password_file}")
        try:
            threads = int(options.get("threads") or "5")
            max_requests = int(options.get("max_requests") or "100")
            delay = float(options.get("delay") or "0.5")
        except ValueError as error:
            raise ExecutionError("threads, delay, and max requests must be numbers") from error
        if not 1 <= threads <= 20:
            raise ExecutionError("brutepyweb threads must be from 1 to 20")
        if not 1 <= max_requests <= 10000:
            raise ExecutionError("brutepyweb max requests must be from 1 to 10000")
        if not 0 <= delay <= 60:
            raise ExecutionError("brutepyweb delay must be from 0 to 60 seconds")
        wrapper = Path(__file__).resolve().parents[1] / "scripts" / "brutepyweb_adapter.py"
        artifact = run_path / "artifacts" / "brutepyweb.jsonl"
        identity = options.get("identity", "").strip()
        identity_arguments = ("--username", identity) if identity else ()
        return CommandSpec(
            executable,
            (
                str(wrapper), "--tool", str(self.script_path(request)),
                "--artifact", str(artifact), "--identity", identity, "--",
                "-u", targets[0].normalized, "-p", str(password_file),
                *identity_arguments,
                "--threads", str(threads), "--delay", str(delay),
                "--max-requests", str(max_requests),
            ),
            "jsonl",
        )

    def route_proxy(self, request: RunRequest, command: CommandSpec) -> CommandSpec:
        self.validate_proxy(request)
        return CommandSpec(
            command.executable,
            command.arguments,
            command.output_format,
            command.companion,
            (*command.environment, *self._proxy_environment(request.proxy)),
        )


class AdapterRegistry:
    """Resolve adapters by catalog key so runtime modules stay data-driven."""

    def __init__(self, adapters: tuple[ToolAdapter, ...] | None = None) -> None:
        installed = adapters or (
            DeclarativeAdapter(), SubfinderAdapter(), DnsxAdapter(), NmapAdapter(),
            HttpxAdapter(), GauAdapter(), FfufAdapter(), TlsxAdapter(), NucleiAdapter(),
            SqlmapAdapter(), BrutepywebAdapter(),
        )
        self._adapters = {adapter.key: adapter for adapter in installed}

    def get(self, key: str) -> ToolAdapter:
        try:
            return self._adapters[key]
        except KeyError as error:
            raise ExecutionError(f"unknown module adapter: {key}") from error
