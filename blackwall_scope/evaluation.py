"""Pure matching and enforcement policy for scope-aware launches."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from .models import OwnershipConfidence, ScopeRule, ScopeStatus, Target, TargetKind


@dataclass(frozen=True, slots=True)
class ScopeEvaluation:
    target: Target
    matched_rule: ScopeRule | None
    scope_status: ScopeStatus | None
    ownership_confidence: OwnershipConfidence
    review_required: bool
    launch_allowed: bool

    @property
    def matched(self) -> bool:
        return self.matched_rule is not None


def _target_host(target: Target) -> str | None:
    if target.kind is TargetKind.DOMAIN:
        return target.normalized.removeprefix("*.")
    if target.kind is TargetKind.URL:
        return urlsplit(target.normalized).hostname
    return None


def rule_matches(rule: ScopeRule, target: Target) -> bool:
    """Return whether a rule covers a target across compatible target types."""
    rule_target = rule.target
    if rule_target.kind is TargetKind.URL:
        return target.kind is TargetKind.URL and rule_target.normalized == target.normalized

    if rule_target.kind is TargetKind.DOMAIN:
        host = _target_host(target)
        if host is None:
            return False
        pattern = rule_target.normalized
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith(f".{suffix}")
        return host == pattern

    if rule_target.kind is TargetKind.CIDR:
        if target.kind not in (TargetKind.IPV4, TargetKind.IPV6):
            return False
        network = ip_network(rule_target.normalized)
        address = ip_address(target.normalized)
        return address.version == network.version and address in network

    return rule_target.kind is target.kind and rule_target.normalized == target.normalized


def _specificity(rule: ScopeRule) -> tuple[int, int]:
    target = rule.target
    if target.kind is TargetKind.URL:
        return (5, len(target.normalized))
    if target.kind in (TargetKind.IPV4, TargetKind.IPV6):
        return (4, len(target.normalized))
    if target.kind is TargetKind.DOMAIN:
        return (2 if target.normalized.startswith("*.") else 3, len(target.normalized))
    if target.kind is TargetKind.CIDR:
        return (1, ip_network(target.normalized).prefixlen)
    return (0, 0)


def evaluate_target(
    target: Target,
    rules: tuple[ScopeRule, ...],
    *,
    enforce: bool,
) -> ScopeEvaluation:
    """Evaluate a target; enforcement blocks explicit exclusions only.

    An unmatched direct target remains launchable. This preserves Blackwall's
    project-optional workflow while still making explicit exclusions effective.
    """
    matches = [rule for rule in rules if rule_matches(rule, target)]
    denied = [rule for rule in matches if rule.scope_status is ScopeStatus.DENIED]
    candidates = denied or matches
    matched = max(candidates, key=_specificity) if candidates else None
    blocked = bool(enforce and matched and matched.scope_status is ScopeStatus.DENIED)
    return ScopeEvaluation(
        target=target,
        matched_rule=matched,
        scope_status=matched.scope_status if matched else None,
        ownership_confidence=(
            matched.ownership_confidence if matched else OwnershipConfidence.UNKNOWN
        ),
        review_required=matched.review_required if matched else False,
        launch_allowed=not blocked,
    )


def evaluate_targets(
    targets: tuple[Target, ...],
    rules: tuple[ScopeRule, ...],
    *,
    enforce: bool,
) -> tuple[ScopeEvaluation, ...]:
    return tuple(evaluate_target(target, rules, enforce=enforce) for target in targets)

