"""Fixed Subfinder -> dnsx -> httpx web-discovery module."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from nullbound_evidence import AssetKind, ParserRegistry
from nullbound_execution import (
    CommandSpec,
    ExecutionError,
    ExecutionManager,
    RunManifest,
    RunRequest,
    RunState,
    RunStore,
)
from nullbound_scope import (
    ExecutionContext,
    ScopeRule,
    ScopeStatus,
    ScopeValidationError,
    Target,
    TargetKind,
    TargetSelection,
    evaluate_targets,
)
from recon_modules import ModuleCatalog, ScanProfile


WEB_DISCOVERY_ID = "web-discovery"
STAGE_MODULE_IDS = ("01", "02", "04")
ARTIFACT_NAMES = {
    "subfinder": "subfinder.jsonl",
    "dnsx": "dnsx.jsonl",
    "httpx": "httpx.jsonl",
}
HTTPX_DISCOVERY_PROFILE = ScanProfile(
    name="Discovery web metadata",
    options=(
        ("Follow redirects", "ENABLED"),
        ("Capture title", "ENABLED"),
        ("Input", "DNSX RESULTS"),
    ),
    arguments=("-l", "{target_file}", "-title", "-tech-detect", "-fr", "-json"),
    output_format="jsonl",
)


StageStarted = Callable[[int, int, RunManifest], None]


@dataclass(frozen=True, slots=True)
class WebDiscoveryResult:
    runs: tuple[RunManifest, ...]
    discovered_domains: int
    resolved_hosts: int
    live_web_services: int
    excluded_targets: int


class WebDiscoveryModule:
    """Coordinate existing launchers without hiding their ordinary run records."""

    def __init__(
        self,
        execution_manager: ExecutionManager,
        module_catalog: ModuleCatalog,
        parsers: ParserRegistry | None = None,
    ) -> None:
        self.execution_manager = execution_manager
        self.module_catalog = module_catalog
        self.parsers = parsers or ParserRegistry.native()

    @staticmethod
    def supports_scope_rule(rule: ScopeRule) -> bool:
        if rule.scope_status is not ScopeStatus.ALLOWED:
            return False
        if rule.target.kind is TargetKind.DOMAIN:
            return True
        if rule.target.kind is TargetKind.URL:
            host = urlsplit(rule.target.normalized).hostname or ""
            base = host.removeprefix("*.")
            return bool(base and "*" not in base and Target.parse(base).kind is TargetKind.DOMAIN)
        return False

    @classmethod
    def scope_seeds(
        cls,
        rules: tuple[ScopeRule, ...],
        selected_rule_ids: Iterable[str],
    ) -> tuple[Target, ...]:
        selected_ids = tuple(dict.fromkeys(str(item) for item in selected_rule_ids))
        if not selected_ids:
            raise ScopeValidationError("select at least one compatible scope item")
        by_id = {rule.id: rule for rule in rules}
        missing = [rule_id for rule_id in selected_ids if rule_id not in by_id]
        if missing:
            raise ScopeValidationError(f"scope item no longer exists: {missing[0]}")

        seeds: list[Target] = []
        incompatible: list[str] = []
        for rule_id in selected_ids:
            rule = by_id[rule_id]
            if not cls.supports_scope_rule(rule):
                incompatible.append(rule_id)
                continue
            if rule.target.kind is TargetKind.URL:
                host = urlsplit(rule.target.normalized).hostname or ""
            else:
                host = rule.target.normalized
            seeds.append(Target(TargetKind.DOMAIN, host.removeprefix("*.")))
        if incompatible:
            raise ScopeValidationError(
                "Web Discovery accepts allowed domain or HTTP/S URL scope items; "
                f"incompatible selection: {', '.join(incompatible)}"
            )
        return cls._dedupe_targets(seeds)

    def preview(
        self,
        seeds: tuple[Target, ...],
        *,
        project_id: str,
        project_name: str,
        scope_enforced: bool,
        timeout_seconds: int | None = None,
    ) -> tuple[tuple[str, CommandSpec], ...]:
        previews: list[tuple[str, CommandSpec]] = []
        for module_id in STAGE_MODULE_IDS:
            request = self._request(
                module_id,
                seeds,
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
                timeout_seconds=timeout_seconds,
            )
            adapter = self.execution_manager.adapters.get(request.module.adapter)
            previews.append((request.module.bin, adapter.preview_command(request, request.module.path)))
        return tuple(previews)

    async def run(
        self,
        seeds: tuple[Target, ...],
        *,
        project_id: str,
        project_name: str,
        project_path: Path,
        scope_rules: tuple[ScopeRule, ...],
        scope_enforced: bool,
        timeout_seconds: int | None = None,
        on_stage_started: StageStarted | None = None,
    ) -> WebDiscoveryResult:
        if not seeds:
            raise ScopeValidationError("Web Discovery needs at least one domain seed")
        await self._preflight(
            seeds,
            project_id=project_id,
            project_name=project_name,
            scope_enforced=scope_enforced,
            timeout_seconds=timeout_seconds,
        )

        runs: list[RunManifest] = []
        excluded = 0

        subfinder = await self._run_stage(
            0, seeds, project_id, project_name, project_path, scope_enforced,
            timeout_seconds, on_stage_started,
        )
        runs.append(subfinder)
        discovered = self._targets_from_run(subfinder, "subfinder", {AssetKind.DOMAIN})
        dns_targets, omitted = self._filter_targets(
            (*seeds, *discovered), scope_rules, scope_enforced
        )
        excluded += omitted
        if not dns_targets:
            return WebDiscoveryResult(tuple(runs), len(discovered), 0, 0, excluded)

        dnsx = await self._run_stage(
            1, dns_targets, project_id, project_name, project_path, scope_enforced,
            timeout_seconds, on_stage_started,
        )
        runs.append(dnsx)
        resolved = self._targets_from_run(
            dnsx, "dnsx", {AssetKind.DOMAIN, AssetKind.IPV4, AssetKind.IPV6}
        )
        http_targets, omitted = self._filter_targets(resolved, scope_rules, scope_enforced)
        excluded += omitted
        if not http_targets:
            return WebDiscoveryResult(
                tuple(runs), len(discovered), len(resolved), 0, excluded
            )

        httpx = await self._run_stage(
            2, http_targets, project_id, project_name, project_path, scope_enforced,
            timeout_seconds, on_stage_started,
        )
        runs.append(httpx)
        live = self._records(httpx, "httpx")
        return WebDiscoveryResult(
            tuple(runs), len(discovered), len(resolved), len(live), excluded
        )

    async def _preflight(
        self,
        targets: tuple[Target, ...],
        *,
        project_id: str,
        project_name: str,
        scope_enforced: bool,
        timeout_seconds: int | None,
    ) -> None:
        requests = tuple(
            self._request(
                module_id,
                targets,
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
                timeout_seconds=timeout_seconds,
            )
            for module_id in STAGE_MODULE_IDS
        )
        health = await asyncio.gather(
            *(self.execution_manager.check_tool(request) for request in requests)
        )
        unavailable = [
            f"{request.module.bin}: {item.detail or item.state}"
            for request, item in zip(requests, health)
            if item.state != "AVAILABLE"
        ]
        if unavailable:
            raise ExecutionError("Web Discovery preflight failed — " + "; ".join(unavailable))

    async def _run_stage(
        self,
        stage_index: int,
        targets: tuple[Target, ...],
        project_id: str,
        project_name: str,
        project_path: Path,
        scope_enforced: bool,
        timeout_seconds: int | None,
        on_stage_started: StageStarted | None,
    ) -> RunManifest:
        request = self._request(
            STAGE_MODULE_IDS[stage_index], targets,
            project_id=project_id,
            project_name=project_name,
            scope_enforced=scope_enforced,
            timeout_seconds=timeout_seconds,
        )
        run = await self.execution_manager.start(request, project_path)
        if on_stage_started is not None:
            on_stage_started(stage_index + 1, len(STAGE_MODULE_IDS), run)
        finished = await self.execution_manager.wait(run.id)
        if finished.state is not RunState.COMPLETED:
            raise ExecutionError(
                f"Web Discovery stopped: {finished.module_bin} {finished.state.value}"
                + (f" — {finished.error}" if finished.error else "")
            )
        if finished.evidence_state == "failed":
            raise ExecutionError(
                f"Web Discovery stopped: {finished.module_bin} evidence indexing failed"
                + (f" — {finished.evidence_error}" if finished.evidence_error else "")
            )
        return finished

    def _request(
        self,
        module_id: str,
        targets: tuple[Target, ...],
        *,
        project_id: str,
        project_name: str,
        scope_enforced: bool,
        timeout_seconds: int | None,
    ) -> RunRequest:
        module = self.module_catalog.get(module_id)
        profile = HTTPX_DISCOVERY_PROFILE if module_id == "04" else module.default_profile
        return RunRequest(
            module=module,
            profile=profile,
            context=ExecutionContext(
                selection=TargetSelection.direct(targets),
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
            ),
            timeout_seconds=timeout_seconds,
        )

    def _records(self, run: RunManifest, parser_key: str):
        artifact_name = ARTIFACT_NAMES[parser_key]
        artifact = next(
            (record for record in run.artifacts if Path(record.path).name.casefold() == artifact_name),
            None,
        )
        if artifact is None:
            return ()
        path = RunStore.resolve_artifact(run, artifact.path)
        try:
            return self.parsers.get(parser_key).parse(path, run_id=run.id)
        except (OSError, ValueError) as error:
            raise ExecutionError(
                f"Web Discovery could not normalize {parser_key} output: {error}"
            ) from error

    def _targets_from_run(
        self,
        run: RunManifest,
        parser_key: str,
        accepted_kinds: set[AssetKind],
    ) -> tuple[Target, ...]:
        targets = []
        for record in self._records(run, parser_key):
            if record.kind not in accepted_kinds:
                continue
            targets.append(Target(TargetKind(record.kind.value), record.value))
        return self._dedupe_targets(targets)

    @classmethod
    def _filter_targets(
        cls,
        targets: Iterable[Target],
        rules: tuple[ScopeRule, ...],
        enforce: bool,
    ) -> tuple[tuple[Target, ...], int]:
        unique = cls._dedupe_targets(targets)
        evaluations = evaluate_targets(unique, rules, enforce=enforce)
        allowed = tuple(item.target for item in evaluations if item.launch_allowed)
        return allowed, len(unique) - len(allowed)

    @staticmethod
    def _dedupe_targets(targets: Iterable[Target]) -> tuple[Target, ...]:
        records: list[Target] = []
        identities: set[tuple[TargetKind, str]] = set()
        for target in targets:
            identity = (target.kind, target.normalized)
            if identity not in identities:
                identities.add(identity)
                records.append(target)
        return tuple(records)
