"""Простой файловый репозиторий (JSON) — без внешних зависимостей.

Хранит всё состояние проекта прогнозирования доверия: приложение, версии,
меры (МОБП), записи об их выполнении/прогнозировании, ПОБП, результаты
верификации и журнал аудита. Формат — один JSON-файл на проект, что
достаточно для учебной/демонстрационной автоматизации и легко читается
человеком (в т.ч. при проверке работы).
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from . import models as m


class Repository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.application: Optional[m.Application] = None
        self.controls: dict[str, m.SecurityControl] = {}
        self.versions: dict[str, m.ApplicationVersion] = {}
        self.executions: dict[str, m.ControlExecution] = {}
        self.pasrs: dict[str, m.PASR] = {}
        self.verifications: dict[str, m.VerificationSample] = {}
        self.audit_log: list[m.AuditLogEntry] = []
        self.policy: str = m.PredictionPolicy.CONDITIONAL.value
        self.substantial_threshold: float = 0.65
        self.borderline_threshold: float = 0.35

        if self.path.exists():
            self.load()

    # ------------------------------------------------------------------ #
    # (де)сериализация
    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_jsonable(obj: Any) -> Any:
        if is_dataclass(obj):
            return {k: Repository._to_jsonable(v) for k, v in asdict(obj).items()}
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, dict):
            return {k: Repository._to_jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [Repository._to_jsonable(v) for v in obj]
        return obj

    def save(self) -> None:
        data = {
            "application": self._to_jsonable(self.application) if self.application else None,
            "controls": {k: self._to_jsonable(v) for k, v in self.controls.items()},
            "versions": {k: self._to_jsonable(v) for k, v in self.versions.items()},
            "executions": {k: self._to_jsonable(v) for k, v in self.executions.items()},
            "pasrs": {k: self._to_jsonable(v) for k, v in self.pasrs.items()},
            "verifications": {k: self._to_jsonable(v) for k, v in self.verifications.items()},
            "audit_log": [self._to_jsonable(v) for v in self.audit_log],
            "policy": self.policy,
            "substantial_threshold": self.substantial_threshold,
            "borderline_threshold": self.borderline_threshold,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def load(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))

        self.application = m.Application(**data["application"]) if data.get("application") else None

        self.controls = {
            k: m.SecurityControl(**v) for k, v in data.get("controls", {}).items()
        }

        self.versions = {}
        for k, v in data.get("versions", {}).items():
            v = dict(v)
            v["changes"] = [
                m.ChangeItem(
                    **{**c, "category": m.ChangeCategory(c["category"])}
                )
                for c in v.get("changes", [])
            ]
            self.versions[k] = m.ApplicationVersion(**v)

        self.executions = {}
        for k, v in data.get("executions", {}).items():
            v = dict(v)
            v["status"] = m.ControlStatus(v["status"])
            v["outcome"] = m.ControlOutcome(v["outcome"])
            self.executions[k] = m.ControlExecution(**v)

        self.pasrs = {}
        for k, v in data.get("pasrs", {}).items():
            v = dict(v)
            v["onf_decision"] = m.ApprovalDecision(v["onf_decision"])
            v["owner_decision"] = m.ApprovalDecision(v["owner_decision"])
            if v.get("substantiality_label"):
                v["substantiality_label"] = m.SubstantialityLabel(v["substantiality_label"])
            self.pasrs[k] = m.PASR(**v)

        self.verifications = {}
        for k, v in data.get("verifications", {}).items():
            v = dict(v)
            v["reexecution_outcome"] = m.ControlOutcome(v["reexecution_outcome"])
            self.verifications[k] = m.VerificationSample(**v)

        self.audit_log = [m.AuditLogEntry(**v) for v in data.get("audit_log", [])]
        self.policy = data.get("policy", m.PredictionPolicy.CONDITIONAL.value)
        self.substantial_threshold = data.get("substantial_threshold", 0.65)
        self.borderline_threshold = data.get("borderline_threshold", 0.35)

    # ------------------------------------------------------------------ #
    # удобные выборки
    # ------------------------------------------------------------------ #

    def executions_for_version(self, version_id: str) -> list[m.ControlExecution]:
        return [e for e in self.executions.values() if e.version_id == version_id]

    def execution_for(self, version_id: str, control_id: str) -> Optional[m.ControlExecution]:
        for e in self.executions.values():
            if e.version_id == version_id and e.control_id == control_id:
                return e
        return None

    def pasrs_for_version(self, version_id: str) -> list[m.PASR]:
        return [p for p in self.pasrs.values() if p.version_id == version_id]

    def log(self, step: str, actor: str, details: str) -> None:
        self.audit_log.append(m.AuditLogEntry(step=step, actor=actor, details=details))
