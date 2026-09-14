"""Доменные модели процесса прогнозирования доверия (ГОСТ Р ИСО/МЭК 27034-7-2020)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------------- #
# Перечисления
# --------------------------------------------------------------------------- #

class PredictionPolicy(str, Enum):
    """Политика применения прогноза, выбираемая группой НСО (п. 9.4)."""

    FORBIDDEN = "forbidden"          # прогнозы не допускаются
    CONDITIONAL = "conditional"      # прогнозы в заранее заданных границах
    UNRESTRICTED = "unrestricted"    # неограниченное использование прогноза


class ChangeCategory(str, Enum):
    """Категория изменения приложения — используется при анализе
    существенности изменения (раздел 7)."""

    CODE = "code"                              # изменения кода / статический анализ
    ARCHITECTURE = "architecture"              # изменения на уровне архитектуры
    TEST_METHODOLOGY = "test_methodology"      # устаревание методики тестирования
    CONFIGURATION = "configuration"            # конфигурационные изменения
    OTHER = "other"


class SubstantialityLabel(str, Enum):
    SUBSTANTIAL = "substantial"        # существенное — прогноз, как правило, неприменим
    BORDERLINE = "borderline"          # пограничное — требуется обоснование НСО
    NOT_SUBSTANTIAL = "not_substantial"  # несущественное — прогноз обычно допустим


class ControlStatus(str, Enum):
    PLANNED = "planned"
    PREDICTED = "predicted"    # заменено ПОБП вместо повторного выполнения
    EXECUTED = "executed"      # мера выполнена фактически


class ControlOutcome(str, Enum):
    PENDING = "pending"
    PASS_ = "pass"
    FAIL = "fail"


class ApprovalDecision(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ActorCategory(str, Enum):
    """Семь категорий участников процесса, упомянутых во введении
    стандарта (п. 0.3) и используемых в матрицах RACI (п. 9.5, раздел 12)."""

    MANAGER = "manager"                # руководитель
    ONF_GROUP = "onf_group"            # группа нормативной структуры организации (НСО)
    PROJECT_TEAM = "project_team"      # проектная команда
    DOMAIN_EXPERT = "domain_expert"    # эксперт предметной области
    AUDITOR = "auditor"                # аудитор
    APP_OWNER = "app_owner"            # владелец приложения
    ACQUIRER = "acquirer"              # приобретающая сторона


class RaciRole(str, Enum):
    R = "R"  # Ответственность (О) — исполняет действие
    A = "A"  # Подотчётность (П) — утверждает результат
    C = "C"  # Консультирование (К) — привлекается обязательно
    I = "I"  # Информирование (И) — уведомляется о результате
    NONE = "-"


# --------------------------------------------------------------------------- #
# Сущности
# --------------------------------------------------------------------------- #

@dataclass
class SecurityControl:
    """МОБП — мера обеспечения безопасности приложений."""

    name: str
    category: str = "general"
    weight: float = 1.0          # относительная значимость меры (0..1..n)
    critical: bool = False       # критическая мера (не подлежит прогнозированию)
    id: str = field(default_factory=lambda: new_id("ctrl"))
    description: str = ""


@dataclass
class ChangeItem:
    """Изменение приложения, подлежащее анализу существенности (раздел 7)."""

    description: str
    category: ChangeCategory
    affected_control_ids: list[str] = field(default_factory=list)
    # экспертная оценка влияния на риск, задаётся аналитиком/экспертом
    # предметной области по результатам анализа риска (0.0 .. 1.0)
    analyst_risk_impact: float = 0.5
    id: str = field(default_factory=lambda: new_id("chg"))
    notes: str = ""


@dataclass
class Application:
    name: str
    owner: str
    id: str = field(default_factory=lambda: new_id("app"))


@dataclass
class ApplicationVersion:
    """Версия приложения. Версия без parent_version_id считается исходной
    («эталонной») — для неё фактический уровень доверия достигается
    только полным выполнением МОБП (без прогноза)."""

    application_id: str
    label: str
    parent_version_id: Optional[str] = None
    id: str = field(default_factory=lambda: new_id("ver"))
    created_at: str = field(default_factory=now_iso)
    changes: list[ChangeItem] = field(default_factory=list)
    target_trust_threshold: float = 0.9   # целевой уровень доверия (0..1)


@dataclass
class ControlExecution:
    """Запись о выполнении (или прогнозировании) конкретной меры (МОБП)
    для конкретной версии приложения."""

    version_id: str
    control_id: str
    status: ControlStatus = ControlStatus.PLANNED
    outcome: ControlOutcome = ControlOutcome.PENDING
    evidence: str = ""
    executed_by: str = ""
    executed_at: str = field(default_factory=now_iso)
    pasr_id: Optional[str] = None   # заполняется, если status == PREDICTED
    id: str = field(default_factory=lambda: new_id("exec"))


@dataclass
class PASR:
    """Прогнозное обоснование безопасности приложения (раздел 9).

    Согласно п. 9.2 стандарта ПОБП должен содержать не менее шести
    обязательных элементов — они соответствуют полям этого класса:

        1. identifiers            — идентификаторы (приложение/версия/мера)
        2. actors                 — действующие лица
        3. circumstances          — обстоятельства прогнозирования
        4. rationale               — собственно обоснование
        5. original_execution_ref — результаты выполнения исходных МОБП
        6. criteria                — критерии достаточности обоснования
    """

    version_id: str
    control_id: str
    identifiers: str
    actors: dict[str, str]                 # {"initiator": .., "onf_group": .., "app_owner": ..}
    circumstances: str
    rationale: str
    original_execution_ref: str
    criteria: str
    id: str = field(default_factory=lambda: new_id("pasr"))
    created_at: str = field(default_factory=now_iso)

    # Двойное утверждение (п. 5.5): ни одна из сторон не может принудить
    # другую к согласию — оба решения независимы.
    onf_decision: ApprovalDecision = ApprovalDecision.PENDING
    onf_justification: str = ""
    owner_decision: ApprovalDecision = ApprovalDecision.PENDING
    owner_justification: str = ""

    substantiality_label: Optional[SubstantialityLabel] = None
    substantiality_score: Optional[float] = None

    @property
    def is_approved(self) -> bool:
        return (
            self.onf_decision == ApprovalDecision.APPROVED
            and self.owner_decision == ApprovalDecision.APPROVED
        )

    @property
    def is_rejected(self) -> bool:
        return (
            self.onf_decision == ApprovalDecision.REJECTED
            or self.owner_decision == ApprovalDecision.REJECTED
        )

    def has_all_required_components(self) -> bool:
        """Проверка качества ПОБП (п. 10.4): все шесть компонентов заполнены."""
        return all(
            bool(v)
            for v in (
                self.identifiers,
                self.actors.get("initiator"),
                self.circumstances,
                self.rationale,
                self.original_execution_ref,
                self.criteria,
            )
        )


@dataclass
class VerificationSample:
    """Результат верификации ПОБП методом выборочного повторного
    выполнения меры (п. 11.2-11.3)."""

    version_id: str
    control_id: str
    pasr_id: str
    reexecution_outcome: ControlOutcome
    matches_expected: bool
    id: str = field(default_factory=lambda: new_id("verif"))
    checked_at: str = field(default_factory=now_iso)
    notes: str = ""


@dataclass
class AuditLogEntry:
    step: str
    actor: str
    details: str
    id: str = field(default_factory=lambda: new_id("log"))
    timestamp: str = field(default_factory=now_iso)
