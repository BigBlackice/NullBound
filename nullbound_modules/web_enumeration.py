"""Scope-driven Web Enumeration using ordinary launcher runs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from nullbound_evidence import AssetKind, AssetRecord, EvidenceStore
from nullbound_execution import (
    CommandSpec,
    ExecutionError,
    ExecutionManager,
    RunManifest,
    RunRequest,
    RunState,
)
from nullbound_scope import (
    ExecutionContext,
    ScopeRule,
    ScopeValidationError,
    Target,
    TargetKind,
    TargetSelection,
    evaluate_targets,
)
from recon_modules import ModuleCatalog, ScanProfile


WEB_ENUMERATION_ID = "web-enumeration"
ENUMERATION_ASSET_KINDS = (
    AssetKind.DOMAIN,
    AssetKind.HOST,
    AssetKind.IPV4,
    AssetKind.IPV6,
    AssetKind.URL,
)
TLS_ASSET_KINDS = (
    AssetKind.DOMAIN,
    AssetKind.HOST,
    AssetKind.IPV4,
    AssetKind.IPV6,
)


@dataclass(frozen=True, slots=True)
class EnumerationStage:
    module_id: str
    purpose: str
    accepted_kinds: tuple[AssetKind, ...]
    profile: ScanProfile
    target_source: str = "assets"
    one_target_per_run: bool = False


@dataclass(frozen=True, slots=True)
class EnumerationChain:
    id: str
    name: str
    description: str
    stages: tuple[EnumerationStage, ...]


QUICK_HTTPX = ScanProfile(
    name="Enumeration quick fingerprint",
    arguments=(
        "-l", "{target_file}", "-status-code", "-title", "-tech-detect",
        "-web-server", "-ip", "-cname", "-cdn", "-json",
    ),
    output_format="jsonl",
)
ARCHIVE_GAU = ScanProfile(
    name="Enumeration archived URLs",
    arguments=("--fp", "{targets}"),
    output_format="jsonl",
)
DEEP_HTTPX = ScanProfile(
    name="Enumeration deep fingerprint",
    arguments=(
        "-l", "{target_file}", "-status-code", "-title", "-tech-detect",
        "-web-server", "-ip", "-cname", "-asn", "-cdn", "-location",
        "-fr", "-json",
    ),
    output_format="jsonl",
)
QUICK_TLSX = ScanProfile(
    name="Enumeration certificate summary",
    arguments=(
        "-l", "{target_file}", "-san", "-cn", "-tls-version", "-cipher",
    ),
    output_format="jsonl",
)
DEEP_TLSX = ScanProfile(
    name="Enumeration full TLS metadata",
    arguments=(
        "-l", "{target_file}", "-san", "-cn", "-so", "-tls-version",
        "-cipher", "-hash", "sha256", "-serial", "-tls-chain",
    ),
    output_format="jsonl",
)
RECURSIVE_FFUF = ScanProfile(
    name="Recursive directory discovery",
    arguments=(
        "-u", "{target}", "-ac", "-recursion",
        "-recursion-strategy", "default",
    ),
    output_format="json",
)


def _chain(
    chain_id: str,
    name: str,
    description: str,
    httpx: ScanProfile,
    tlsx: ScanProfile,
    *,
    archive: bool = False,
) -> EnumerationChain:
    stages = []
    if archive:
        stages.append(EnumerationStage(
            "05", "ARCHIVED URL ENUMERATION", (AssetKind.DOMAIN,),
            ARCHIVE_GAU, "anchor",
        ))
    stages.extend((
        EnumerationStage("04", "HTTP SERVICE FINGERPRINTING", ENUMERATION_ASSET_KINDS, httpx),
        EnumerationStage("06", "TLS AND CERTIFICATE ENUMERATION", TLS_ASSET_KINDS, tlsx),
    ))
    return EnumerationChain(
        chain_id,
        name,
        description,
        tuple(stages),
    )


WEB_ENUMERATION_CHAINS = (
    _chain(
        "quick", "Quick HTTP + TLS", "Fast service and certificate inventory",
        QUICK_HTTPX, QUICK_TLSX,
    ),
    _chain(
        "deep", "Archive + Deep HTTP + TLS",
        "Archived URLs, expanded HTTP metadata, and TLS chains",
        DEEP_HTTPX, DEEP_TLSX, archive=True,
    ),
    EnumerationChain(
        "directories",
        "HTTP + Recursive Directories",
        "Probe web services, then brute directories to a bounded depth",
        (
            EnumerationStage(
                "04", "HTTP SERVICE FINGERPRINTING", ENUMERATION_ASSET_KINDS,
                QUICK_HTTPX,
            ),
            EnumerationStage(
                "07", "RECURSIVE DIRECTORY BRUTE", (AssetKind.URL,),
                RECURSIVE_FFUF, one_target_per_run=True,
            ),
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class EnumerationAssetTarget:
    kind: AssetKind
    target: Target


@dataclass(frozen=True, slots=True)
class WebEnumerationSummary:
    chain: EnumerationChain
    scope_label: str
    compatible_count: int
    omitted_count: int
    preview: tuple[EnumerationAssetTarget, ...]
    seed_target: Target | None
    include_subdomains: bool


@dataclass(frozen=True, slots=True)
class WebEnumerationResult:
    runs: tuple[RunManifest, ...]
    target_count: int
    omitted_count: int


StageStarted = Callable[[int, int, RunManifest], None]


class WebEnumerationModule:
    """Run a selected built-in chain against one explicit project scope rule."""

    def __init__(
        self,
        execution_manager: ExecutionManager,
        module_catalog: ModuleCatalog,
        chains: tuple[EnumerationChain, ...] = WEB_ENUMERATION_CHAINS,
    ) -> None:
        self.execution_manager = execution_manager
        self.module_catalog = module_catalog
        self.chains = chains

    def get_chain(self, chain_id: str) -> EnumerationChain:
        try:
            return next(chain for chain in self.chains if chain.id == chain_id)
        except StopIteration as error:
            raise ScopeValidationError(f"unknown Web Enumeration chain: {chain_id}") from error

    @staticmethod
    def _target(asset: AssetRecord) -> EnumerationAssetTarget:
        kind = {
            AssetKind.DOMAIN: TargetKind.DOMAIN,
            AssetKind.HOST: TargetKind.DOMAIN,
            AssetKind.IPV4: TargetKind.IPV4,
            AssetKind.IPV6: TargetKind.IPV6,
            AssetKind.URL: TargetKind.URL,
        }.get(asset.kind)
        if kind is None:
            raise ScopeValidationError(f"unsupported enumeration asset kind: {asset.kind.value}")
        return EnumerationAssetTarget(asset.kind, Target(kind, asset.normalized_key))

    @staticmethod
    def _dedupe_targets(
        targets: Iterable[EnumerationAssetTarget],
    ) -> tuple[EnumerationAssetTarget, ...]:
        records: list[EnumerationAssetTarget] = []
        identities: set[tuple[TargetKind, str]] = set()
        for item in targets:
            identity = (item.target.kind, item.target.normalized)
            if identity not in identities:
                identities.add(identity)
                records.append(item)
        return tuple(records)

    def summarize(
        self,
        store: EvidenceStore,
        rule_id: str,
        chain_id: str,
        *,
        preview_limit: int = 8,
    ) -> WebEnumerationSummary:
        chain = self.get_chain(chain_id)
        kinds = tuple(dict.fromkeys(
            kind for stage in chain.stages for kind in stage.accepted_kinds
        ))
        rules = {str(rule["id"]): rule for rule in store.list_scope_rules()}
        rule = rules.get(rule_id)
        if rule is None or str(rule["scope_status"]) == "denied":
            raise ScopeValidationError("select an available project scope item")
        scope_target = Target(
            TargetKind(str(rule["target_kind"])), str(rule["original_target"])
        )
        include_subdomains = (
            scope_target.kind is TargetKind.DOMAIN
            and scope_target.normalized.startswith("*.")
        )
        seed_target = (
            Target(TargetKind.DOMAIN, scope_target.normalized.removeprefix("*."))
            if scope_target.kind is TargetKind.DOMAIN else None
        )
        if any(stage.target_source == "anchor" for stage in chain.stages) and seed_target is None:
            raise ScopeValidationError(
                f"{chain.name} requires a domain scope item"
            )
        compatible = store.count_enumeration_assets(rule_id, kinds)
        total = store.count_enumeration_assets(rule_id)
        preview = self._dedupe_targets(
            self._target(asset)
            for asset in store.preview_enumeration_assets(
                rule_id, kinds, limit=preview_limit
            )
        )
        return WebEnumerationSummary(
            chain, str(rule["original_target"]), compatible,
            max(total - compatible, 0), preview, seed_target, include_subdomains,
        )

    def resolve_targets(
        self,
        store: EvidenceStore,
        rule_id: str,
        chain_id: str,
    ) -> tuple[EnumerationAssetTarget, ...]:
        chain = self.get_chain(chain_id)
        kinds = tuple(dict.fromkeys(
            kind for stage in chain.stages for kind in stage.accepted_kinds
        ))
        targets = self._dedupe_targets(
            self._target(asset)
            for asset in store.iter_enumeration_assets(rule_id, kinds)
        )
        if not targets:
            raise ScopeValidationError(
                "the selected scope item has no compatible indexed web assets; "
                "run Web Discovery first"
            )
        return targets

    @staticmethod
    def _stage_targets(
        targets: tuple[EnumerationAssetTarget, ...],
        stage: EnumerationStage,
    ) -> tuple[Target, ...]:
        accepted = set(stage.accepted_kinds)
        return tuple(item.target for item in targets if item.kind in accepted)

    def preview(
        self,
        summary: WebEnumerationSummary,
        *,
        project_id: str,
        project_name: str,
        scope_enforced: bool,
        timeout_seconds: int | None = None,
        wordlist: str = "",
        recursion_depth: int = 2,
    ) -> tuple[tuple[EnumerationStage, CommandSpec], ...]:
        previews: list[tuple[EnumerationStage, CommandSpec]] = []
        for stage in summary.chain.stages:
            targets = (
                (summary.seed_target,)
                if stage.target_source == "anchor" and summary.seed_target is not None
                else self._stage_targets(summary.preview, stage)
            )
            if not targets:
                continue
            if stage.one_target_per_run:
                targets = targets[:1]
            request = self._request(
                stage, targets,
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
                timeout_seconds=timeout_seconds,
                include_subdomains=summary.include_subdomains,
                wordlist=wordlist,
                recursion_depth=recursion_depth,
            )
            adapter = self.execution_manager.adapters.get(request.module.adapter)
            previews.append((stage, adapter.preview_command(request, request.module.path)))
        return tuple(previews)

    async def run(
        self,
        store: EvidenceStore,
        rule_id: str,
        chain_id: str,
        *,
        project_id: str,
        project_name: str,
        project_path: Path,
        scope_rules: tuple[ScopeRule, ...],
        scope_enforced: bool,
        timeout_seconds: int | None = None,
        wordlist: str = "",
        recursion_depth: int = 2,
        on_stage_started: StageStarted | None = None,
    ) -> WebEnumerationResult:
        chain = self.get_chain(chain_id)
        if any(stage.module_id == "07" for stage in chain.stages):
            wordlist_path = Path(wordlist).expanduser().resolve()
            if not wordlist_path.is_file():
                raise ScopeValidationError(f"ffuf wordlist does not exist: {wordlist_path}")
            if not 1 <= recursion_depth <= 10:
                raise ScopeValidationError("ffuf recursion depth must be from 1 to 10")
            wordlist = str(wordlist_path)
        summary = self.summarize(store, rule_id, chain_id, preview_limit=8)
        expanded = self.resolve_targets(store, rule_id, chain_id)
        evaluations = evaluate_targets(
            tuple(item.target for item in expanded), scope_rules, enforce=scope_enforced
        )
        allowed = {
            (item.target.kind, item.target.normalized)
            for item in evaluations if item.launch_allowed
        }
        targets = tuple(
            item for item in expanded
            if (item.target.kind, item.target.normalized) in allowed
        )
        excluded = len(expanded) - len(targets)
        if not targets:
            raise ScopeValidationError("scope enforcement excluded every enumeration target")

        preflight_requests = tuple(
            self._request(
                stage,
                (summary.seed_target,)
                if stage.target_source == "anchor" and summary.seed_target is not None
                else (self._stage_targets(targets, stage)[:1]
                      if stage.one_target_per_run else self._stage_targets(targets, stage)),
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
                timeout_seconds=timeout_seconds,
                include_subdomains=summary.include_subdomains,
                wordlist=wordlist,
                recursion_depth=recursion_depth,
            )
            for stage in chain.stages
            if stage.target_source == "anchor" or self._stage_targets(targets, stage)
        )
        health = await asyncio.gather(
            *(self.execution_manager.check_tool(request) for request in preflight_requests)
        )
        unavailable = [
            f"{request.module.bin}: {item.detail or item.state}"
            for request, item in zip(preflight_requests, health)
            if item.state != "AVAILABLE"
        ]
        if unavailable:
            raise ExecutionError("Web Enumeration preflight failed — " + "; ".join(unavailable))

        runs: list[RunManifest] = []
        for index, stage in enumerate(chain.stages, start=1):
            if stage.target_source == "anchor":
                stage_targets = (summary.seed_target,) if summary.seed_target is not None else ()
            else:
                current = self.resolve_targets(store, rule_id, chain_id)
                current_evaluations = evaluate_targets(
                    tuple(item.target for item in current), scope_rules,
                    enforce=scope_enforced,
                )
                allowed_current = {
                    (item.target.kind, item.target.normalized)
                    for item in current_evaluations if item.launch_allowed
                }
                current = tuple(
                    item for item in current
                    if (item.target.kind, item.target.normalized) in allowed_current
                )
                stage_targets = self._stage_targets(current, stage)
            if not stage_targets:
                continue
            batches = (
                tuple((target,) for target in stage_targets)
                if stage.one_target_per_run else (stage_targets,)
            )
            for batch in batches:
                request = self._request(
                    stage, batch,
                    project_id=project_id,
                    project_name=project_name,
                    scope_enforced=scope_enforced,
                    timeout_seconds=timeout_seconds,
                    include_subdomains=summary.include_subdomains,
                    wordlist=wordlist,
                    recursion_depth=recursion_depth,
                )
                run = await self.execution_manager.start(request, project_path)
                if on_stage_started is not None:
                    on_stage_started(index, len(chain.stages), run)
                finished = await self.execution_manager.wait(run.id)
                runs.append(finished)
                if finished.state is not RunState.COMPLETED:
                    raise ExecutionError(
                        f"Web Enumeration stopped: {finished.module_bin} {finished.state.value}"
                        + (f" — {finished.error}" if finished.error else "")
                    )
                if finished.evidence_state == "failed":
                    raise ExecutionError(
                        f"Web Enumeration stopped: {finished.module_bin} evidence indexing failed"
                        + (f" — {finished.evidence_error}" if finished.evidence_error else "")
                    )
        return WebEnumerationResult(tuple(runs), len(targets), excluded)

    def _request(
        self,
        stage: EnumerationStage,
        targets: tuple[Target, ...],
        *,
        project_id: str,
        project_name: str,
        scope_enforced: bool,
        timeout_seconds: int | None,
        include_subdomains: bool,
        wordlist: str,
        recursion_depth: int,
    ) -> RunRequest:
        module = self.module_catalog.get(stage.module_id)
        profile = stage.profile
        if stage.target_source == "anchor" and include_subdomains:
            profile = ScanProfile(
                name=profile.name,
                arguments=("--subs", *profile.arguments),
                output_format=profile.output_format,
            )
        options = (
            (("wordlist", wordlist), ("recursion_depth", str(recursion_depth)))
            if stage.module_id == "07" else ()
        )
        return RunRequest(
            module=module,
            profile=profile,
            context=ExecutionContext(
                selection=TargetSelection.scope_anchor(targets),
                project_id=project_id,
                project_name=project_name,
                scope_enforced=scope_enforced,
            ),
            options=options,
            timeout_seconds=timeout_seconds,
        )
