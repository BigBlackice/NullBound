"""Atomic filesystem persistence for a project's editable scope document."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from uuid import uuid4

from .models import ScopeDocument, ScopeRule, ScopeValidationError, Target, TargetSet


SCOPE_DOCUMENT_NAME = "scope.json"


class ScopeStore:
    """Read and edit one project's target sets and scope rules."""

    def __init__(self, project_path: Path) -> None:
        self.project_path = Path(project_path).expanduser().resolve(strict=False)
        self.path = self.project_path / SCOPE_DOCUMENT_NAME

    def load(self) -> ScopeDocument:
        if not self.path.exists():
            return ScopeDocument()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ScopeValidationError(f"cannot read scope document: {self.path}") from error
        if not isinstance(payload, dict):
            raise ScopeValidationError("scope document must contain a JSON object")
        return ScopeDocument.from_mapping(payload)

    def save(self, document: ScopeDocument) -> ScopeDocument:
        self.project_path.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(document.to_mapping(), indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return document

    def add_target_set(
        self,
        name: str,
        targets: tuple[Target, ...],
        description: str = "",
    ) -> TargetSet:
        document = self.load()
        target_set = TargetSet(
            id=self._next_id((item.id for item in document.target_sets), "TS"),
            name=name,
            description=description,
            targets=targets,
        )
        self.save(replace(document, target_sets=(*document.target_sets, target_set)))
        return target_set

    def put_target_set(self, target_set: TargetSet) -> TargetSet:
        document = self.load()
        items = tuple(item for item in document.target_sets if item.id != target_set.id)
        self.save(replace(document, target_sets=(*items, target_set)))
        return target_set

    def remove_target_set(self, target_set_id: str) -> None:
        document = self.load()
        items = tuple(item for item in document.target_sets if item.id != target_set_id)
        if len(items) == len(document.target_sets):
            raise KeyError(target_set_id)
        self.save(replace(document, target_sets=items))

    def add_rule(self, rule: ScopeRule | None = None, **values: object) -> ScopeRule:
        document = self.load()
        if rule is None:
            rule = ScopeRule(
                id=self._next_id((item.id for item in document.rules), "SC"),
                **values,
            )
        self.save(replace(document, rules=(*document.rules, rule)))
        return rule

    def put_rule(self, rule: ScopeRule) -> ScopeRule:
        document = self.load()
        items = tuple(item for item in document.rules if item.id != rule.id)
        self.save(replace(document, rules=(*items, rule)))
        return rule

    def remove_rule(self, rule_id: str) -> None:
        document = self.load()
        items = tuple(item for item in document.rules if item.id != rule_id)
        if len(items) == len(document.rules):
            raise KeyError(rule_id)
        self.save(replace(document, rules=items))

    @staticmethod
    def _next_id(identifiers: object, prefix: str) -> str:
        numbers = [int(value.split("-", 1)[1]) for value in identifiers]
        return f"{prefix}-{max(numbers, default=0) + 1:04d}"

