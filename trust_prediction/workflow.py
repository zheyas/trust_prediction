"""Оркестрация десятишагового процесса осуществления ПОБП
(ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 12.2):

    1.  НСО задаёт методологию прогнозирования
    2.  Инициирование прогноза проектной командой
    3.  Анализ рисков новой версии
    4.  Подготовка ПОБП
    5.  Согласование с владельцем приложения
    6.  Утверждение прогноза (двойное)
    7.  Выполнение оставшихся МОБП
    8.  Проверка и верификация результатов
    9.  Аудит ПОБП и фактического уровня доверия
    10. Формирование отчёта об ожидаемом уровне доверия

Каждый шаг фиксируется в журнале аудита (Repository.audit_log) с
указанием исполнителя и времени — это прямое требование прозрачности и
подотчётности, пронизывающее весь стандарт (документированные
обоснования, п. 8.2; двойное утверждение, п. 5.5; аудируемость, раздел 10).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import audit as audit_mod
from . import pasr as pasr_mod
from . import raci
from . import substantiality as sub_mod
from . import trust as trust_mod
from .models import (
    Application,
    ApplicationVersion,
    ApprovalDecision,
    ChangeItem,
    ControlExecution,
    ControlOutcome,
    ControlStatus,
    PASR,
    PredictionPolicy,
    SecurityControl,
)
from .storage import Repository


class WorkflowError(Exception):
    """Нарушение процедурных требований стандарта (например, попытка
    прогнозировать при политике FORBIDDEN, или утвердить ПОБП без
    заполнения обязательных компонентов)."""


@dataclass
class StepResult:
    step: int
    title: str
    ok: bool
    message: str
    payload: dict = field(default_factory=dict)


class TrustPredictionWorkflow:
    def __init__(self, repo: Repository):
        self.repo = repo

    # ------------------------------------------------------------------ #
    # Инициализация приложения и мер
    # ------------------------------------------------------------------ #

    def init_application(self, name: str, owner: str) -> Application:
        app = Application(name=name, owner=owner)
        self.repo.application = app
        self.repo.log("init", owner, f"Зарегистрировано приложение «{name}», владелец: {owner}")
        self.repo.save()
        return app

    def add_control(self, name: str, category: str = "general", weight: float = 1.0, critical: bool = False, description: str = "") -> SecurityControl:
        ctrl = SecurityControl(name=name, category=category, weight=weight, critical=critical, description=description)
        self.repo.controls[ctrl.id] = ctrl
        self.repo.save()
        return ctrl

    def new_version(self, label: str, parent_version_id: str | None = None, target_trust_threshold: float = 0.9) -> ApplicationVersion:
        if not self.repo.application:
            raise WorkflowError("сначала выполните init_application()")
        ver = ApplicationVersion(
            application_id=self.repo.application.id,
            label=label,
            parent_version_id=parent_version_id,
            target_trust_threshold=target_trust_threshold,
        )
        self.repo.versions[ver.id] = ver
        self.repo.save()
        return ver

    def add_change(self, version_id: str, description: str, category, affected_control_ids: list[str], analyst_risk_impact: float, notes: str = "") -> ChangeItem:
        ver = self.repo.versions[version_id]
        change = ChangeItem(
            description=description,
            category=category,
            affected_control_ids=affected_control_ids,
            analyst_risk_impact=analyst_risk_impact,
            notes=notes,
        )
        ver.changes.append(change)
        self.repo.save()
        return change

    def record_reference_execution(self, version_id: str, control_id: str, outcome: ControlOutcome, evidence: str, executed_by: str) -> ControlExecution:
        """Фиксирует фактическое выполнение МОБП для эталонной (исходной)
        версии — источник «результатов исходных МОБП» для будущих ПОБП."""
        exe = ControlExecution(
            version_id=version_id,
            control_id=control_id,
            status=ControlStatus.EXECUTED,
            outcome=outcome,
            evidence=evidence,
            executed_by=executed_by,
        )
        self.repo.executions[exe.id] = exe
        self.repo.save()
        return exe

    # ------------------------------------------------------------------ #
    # Шаг 1 — НСО задаёт методологию прогнозирования (п. 9.4, 12.2.1)
    # ------------------------------------------------------------------ #

    def step1_set_policy(
        self,
        policy: PredictionPolicy,
        actor: str,
        substantial_threshold: float = 0.65,
        borderline_threshold: float = 0.35,
    ) -> StepResult:
        self.repo.policy = policy.value
        self.repo.substantial_threshold = substantial_threshold
        self.repo.borderline_threshold = borderline_threshold
        self.repo.log(
            "step1", actor,
            f"Политика прогнозирования: {policy.value}; пороги существенности: "
            f"substantial>={substantial_threshold}, borderline>={borderline_threshold}",
        )
        self.repo.save()
        return StepResult(1, raci.STEPS[0], True, f"Политика группы НСО установлена: {policy.value}")

    # ------------------------------------------------------------------ #
    # Шаг 2 — инициирование прогноза
    # ------------------------------------------------------------------ #

    def step2_initiate(self, version_id: str, initiator: str) -> StepResult:
        if self.repo.policy == PredictionPolicy.FORBIDDEN.value:
            raise WorkflowError("Политика НСО запрещает прогнозирование (FORBIDDEN) — шаг 2 недоступен")
        self.repo.log("step2", initiator, f"Инициировано прогнозирование доверия для версии {version_id}")
        self.repo.save()
        return StepResult(2, raci.STEPS[1], True, "Прогноз инициирован проектной командой")

    # ------------------------------------------------------------------ #
    # Шаг 3 — анализ рисков новой версии (раздел 7)
    # ------------------------------------------------------------------ #

    def step3_risk_analysis(self, version_id: str, actor: str) -> StepResult:
        ver = self.repo.versions[version_id]
        assessments = sub_mod.assess_changes(
            ver.changes, self.repo.substantial_threshold, self.repo.borderline_threshold
        )
        recommendations = {}
        for ctrl_id in self.repo.controls:
            worst = sub_mod.worst_label_for_control(ctrl_id, ver.changes, assessments)
            if worst is None:
                recommendations[ctrl_id] = ("not_affected", None)
            else:
                recommendations[ctrl_id] = (worst.label.value, worst.score)

        self.repo.log(
            "step3", actor,
            f"Анализ риска: {len(ver.changes)} изменений; "
            f"существенных={sum(1 for a in assessments if a.label.value == 'substantial')}, "
            f"пограничных={sum(1 for a in assessments if a.label.value == 'borderline')}, "
            f"несущественных={sum(1 for a in assessments if a.label.value == 'not_substantial')}",
        )
        self.repo.save()
        return StepResult(
            3, raci.STEPS[2], True, "Анализ риска выполнен",
            payload={"assessments": assessments, "control_recommendations": recommendations},
        )

    # ------------------------------------------------------------------ #
    # Шаг 4 — подготовка ПОБП (раздел 9)
    # ------------------------------------------------------------------ #

    def step4_prepare_pasr(
        self,
        version_id: str,
        control_id: str,
        initiator: str,
        onf_actor: str,
        app_owner_actor: str,
        circumstances: str,
        rationale: str,
        criteria: str,
    ) -> StepResult:
        ver = self.repo.versions[version_id]
        if self.repo.policy == PredictionPolicy.FORBIDDEN.value:
            raise WorkflowError("Политика НСО запрещает прогнозирование (FORBIDDEN)")

        assessments = sub_mod.assess_changes(ver.changes, self.repo.substantial_threshold, self.repo.borderline_threshold)
        worst = sub_mod.worst_label_for_control(control_id, ver.changes, assessments)

        if worst is not None and worst.label.value == "substantial":
            raise WorkflowError(
                f"Изменения, влияющие на меру {control_id}, классифицированы как существенные "
                f"(score={worst.score}) — согласно разделу 7 стандарта прогноз, как правило, неприменим. "
                f"Мера должна быть выполнена фактически (см. step7_execute)."
            )

        if worst is not None and worst.label.value == "borderline" and self.repo.policy == PredictionPolicy.CONDITIONAL.value:
            # допустимо, но требует явного обоснования — не блокируем, только помечаем
            pass

        if not ver.parent_version_id:
            raise WorkflowError("У версии нет эталонной (родительской) версии — прогнозировать не с чего")

        ref_exec = self.repo.execution_for(ver.parent_version_id, control_id)
        if not ref_exec or ref_exec.outcome != ControlOutcome.PASS_:
            raise WorkflowError(
                "Для эталонной версии отсутствует успешное фактическое выполнение этой меры — "
                "прогноз строить не на чем (п. 5.2: нужен подтверждённый фактический уровень доверия)"
            )

        pasr = pasr_mod.build_pasr(
            version_id=version_id,
            control_id=control_id,
            initiator=initiator,
            onf_actor=onf_actor,
            app_owner_actor=app_owner_actor,
            circumstances=circumstances,
            rationale=rationale,
            original_execution_ref=f"{ref_exec.id} ({ref_exec.evidence})",
            criteria=criteria,
        )
        if worst is not None:
            pasr.substantiality_label = worst.label
            pasr.substantiality_score = worst.score

        self.repo.pasrs[pasr.id] = pasr

        exe = ControlExecution(
            version_id=version_id,
            control_id=control_id,
            status=ControlStatus.PREDICTED,
            outcome=ControlOutcome.PENDING,
            evidence=f"перенесено через ПОБП {pasr.id}",
            executed_by=initiator,
            pasr_id=pasr.id,
        )
        self.repo.executions[exe.id] = exe

        self.repo.log("step4", initiator, f"Подготовлен проект ПОБП {pasr.id} для меры {control_id}")
        self.repo.save()
        return StepResult(4, raci.STEPS[3], True, f"ПОБП {pasr.id} подготовлен", payload={"pasr": pasr})

    # ------------------------------------------------------------------ #
    # Шаг 5 — согласование с владельцем приложения (комментарий, не решение)
    # ------------------------------------------------------------------ #

    def step5_coordinate_with_owner(self, pasr_id: str, actor: str, comment: str) -> StepResult:
        self.repo.log("step5", actor, f"Согласование ПОБП {pasr_id} с владельцем приложения: {comment}")
        self.repo.save()
        return StepResult(5, raci.STEPS[4], True, "Согласование зафиксировано")

    # ------------------------------------------------------------------ #
    # Шаг 6 — утверждение прогноза (двойное, п. 5.5)
    # ------------------------------------------------------------------ #

    def step6_approve(self, pasr_id: str, party: str, decision: ApprovalDecision, actor: str, justification: str = "") -> StepResult:
        pasr = self.repo.pasrs[pasr_id]
        if not pasr.has_all_required_components():
            raise WorkflowError("ПОБП не содержит все шесть обязательных компонентов (п. 9.2) — утверждение невозможно")

        pasr_mod.decide(pasr, party, decision, justification)
        self.repo.log("step6", actor, f"Решение стороны «{party}» по ПОБП {pasr_id}: {decision.value} ({justification})")

        if pasr.is_approved:
            # выполнение считается перенесённым — можно (не обязательно) отметить исход прогнозируемой меры
            exe = self.repo.execution_for(pasr.version_id, pasr.control_id)
            if exe:
                exe.outcome = ControlOutcome.PASS_
        elif pasr.is_rejected:
            exe = self.repo.execution_for(pasr.version_id, pasr.control_id)
            if exe:
                exe.status = ControlStatus.PLANNED
                exe.outcome = ControlOutcome.PENDING
                exe.pasr_id = None
            self.repo.log("step6", actor, f"ПОБП {pasr_id} отклонён — мера {pasr.control_id} требует фактического выполнения")

        self.repo.save()
        status = "УТВЕРЖДЕНО" if pasr.is_approved else ("ОТКЛОНЕНО" if pasr.is_rejected else "ОЖИДАЕТ ВТОРОЙ СТОРОНЫ")
        return StepResult(6, raci.STEPS[5], True, f"ПОБП {pasr_id}: {status}", payload={"pasr": pasr})

    # ------------------------------------------------------------------ #
    # Шаг 7 — выполнение оставшихся МОБП
    # ------------------------------------------------------------------ #

    def step7_execute_control(self, version_id: str, control_id: str, outcome: ControlOutcome, evidence: str, executed_by: str) -> StepResult:
        exe = self.repo.execution_for(version_id, control_id)
        if exe is None:
            exe = ControlExecution(version_id=version_id, control_id=control_id)
            self.repo.executions[exe.id] = exe
        exe.status = ControlStatus.EXECUTED
        exe.outcome = outcome
        exe.evidence = evidence
        exe.executed_by = executed_by
        exe.pasr_id = None
        self.repo.log("step7", executed_by, f"Мера {control_id} выполнена фактически, результат={outcome.value}")
        self.repo.save()
        return StepResult(7, raci.STEPS[6], True, f"Мера {control_id} выполнена ({outcome.value})")

    # ------------------------------------------------------------------ #
    # Шаг 8 — проверка и верификация результатов (раздел 11)
    # ------------------------------------------------------------------ #

    def step8_verify(self, version_id: str, actor: str, sampling_rate: float = 0.34, rng_seed: int | None = 42, simulate_mismatch_for: list[str] | None = None) -> StepResult:
        version_pasrs = self.repo.pasrs_for_version(version_id)
        critical_ids = {cid for cid, c in self.repo.controls.items() if c.critical}
        sample = audit_mod.select_verification_sample(version_pasrs, critical_ids, sampling_rate, rng_seed)

        simulate_mismatch_for = set(simulate_mismatch_for or [])
        results = []
        for p in sample:
            outcome = ControlOutcome.FAIL if p.control_id in simulate_mismatch_for else ControlOutcome.PASS_
            v = audit_mod.verify_pasr(p, outcome)
            self.repo.verifications[v.id] = v
            results.append(v)

        self.repo.log("step8", actor, f"Верифицировано {len(results)} из {len(version_pasrs)} ПОБП (sampling_rate={sampling_rate})")
        self.repo.save()
        return StepResult(8, raci.STEPS[7], True, f"Верификация выполнена: {len(results)} мер проверено", payload={"verifications": results})

    # ------------------------------------------------------------------ #
    # Шаг 9 — аудит ПОБП и фактического уровня доверия (раздел 10)
    # ------------------------------------------------------------------ #

    def step9_audit(self, version_id: str, actor: str) -> StepResult:
        version_pasrs = self.repo.pasrs_for_version(version_id)
        verifications = [v for v in self.repo.verifications.values() if v.version_id == version_id]
        summary = audit_mod.audit_summary(version_pasrs, verifications)
        self.repo.log("step9", actor, f"Аудит завершён: вердикт={summary['verdict']}, "
                                       f"ПОБП с замечаниями={summary['pasr_quality_issues']}, "
                                       f"расхождений верификации={summary['verification_mismatches']}")
        self.repo.save()
        return StepResult(9, raci.STEPS[8], True, f"Аудит: {summary['verdict']}", payload={"summary": summary})

    # ------------------------------------------------------------------ #
    # Шаг 10 — формирование отчёта об ожидаемом уровне доверия (раздел 13)
    # ------------------------------------------------------------------ #

    def step10_assess(self, version_id: str, actor: str) -> StepResult:
        ver = self.repo.versions[version_id]
        executions = self.repo.executions_for_version(version_id)
        verifications = [v for v in self.repo.verifications.values() if v.version_id == version_id]

        expected = trust_mod.compute_expected_trust(
            version_id, self.repo.controls, executions, self.repo.pasrs, ver.target_trust_threshold, verifications
        )

        actual_ref = None
        if ver.parent_version_id:
            ref_ver = self.repo.versions[ver.parent_version_id]
            ref_executions = self.repo.executions_for_version(ver.parent_version_id)
            actual_ref = trust_mod.compute_actual_trust(
                ver.parent_version_id, self.repo.controls, ref_executions, ref_ver.target_trust_threshold
            )

        self.repo.log(
            "step10", actor,
            f"Ожидаемый уровень доверия версии {ver.label}: {expected.as_percent()} "
            f"(цель {ver.target_trust_threshold * 100:.0f}%) -> "
            f"{'ДОСТИГНУТ' if expected.meets_target else 'НЕ ДОСТИГНУТ'}",
        )
        self.repo.save()
        return StepResult(
            10, raci.STEPS[9], True,
            f"Ожидаемый уровень доверия: {expected.as_percent()}",
            payload={"expected": expected, "actual_reference": actual_ref},
        )
