"""Расчёт уровней доверия (ГОСТ Р ИСО/МЭК 27034-7-2020, разделы 5 и 8).

Три уровня доверия, определяемые стандартом:

    Фактический уровень доверия — достигнут реальным выполнением МОБП
                                    для эталонной версии приложения.
    Ожидаемый уровень доверия   — для новой версии: комбинация мер,
                                    выполненных заново, и мер, перенесённых
                                    через утверждённый и (при необходимости)
                                    верифицированный ПОБП.
    Целевой уровень доверия     — требование, заданное владельцем
                                    приложения (version.target_trust_threshold).

Стандарт не задаёт единой числовой шкалы доверия — она качественная.
Для автоматизации мы вводим прозрачную количественную модель: уровень
доверия = доля суммарного веса мер (МОБП), которые либо фактически
выполнены с результатом PASS, либо законно перенесены через утверждённый
ПОБП, от общего веса релевантных мер. Модель — реализационное решение,
её веса/пороги настраиваются через SecurityControl.weight и
ApplicationVersion.target_trust_threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    ControlExecution,
    ControlOutcome,
    ControlStatus,
    PASR,
    SecurityControl,
    SubstantialityLabel,
    VerificationSample,
)


@dataclass
class ControlTrustBreakdown:
    control_id: str
    control_name: str
    weight: float
    counted: bool
    reason: str


@dataclass
class TrustAssessment:
    version_id: str
    total_weight: float
    counted_weight: float
    fraction: float                 # 0..1
    target_threshold: float
    meets_target: bool
    breakdown: list[ControlTrustBreakdown] = field(default_factory=list)

    def as_percent(self) -> str:
        return f"{self.fraction * 100:.1f}%"


def compute_actual_trust(
    version_id: str,
    controls: dict[str, SecurityControl],
    executions: list[ControlExecution],
    target_threshold: float,
) -> TrustAssessment:
    """Фактический уровень доверия: считаются только меры, выполненные
    реально (status == EXECUTED) с результатом PASS. Прогнозы (PREDICTED)
    в фактический уровень не входят по определению — это отдельная,
    «ожидаемая» часть доверия."""

    by_control = {e.control_id: e for e in executions if e.version_id == version_id}
    total_weight = sum(c.weight for c in controls.values())
    counted_weight = 0.0
    breakdown: list[ControlTrustBreakdown] = []

    for cid, ctrl in controls.items():
        exe = by_control.get(cid)
        if exe and exe.status == ControlStatus.EXECUTED and exe.outcome == ControlOutcome.PASS_:
            counted_weight += ctrl.weight
            breakdown.append(
                ControlTrustBreakdown(cid, ctrl.name, ctrl.weight, True, "мера фактически выполнена, результат PASS")
            )
        else:
            reason = "мера не выполнена" if not exe else f"статус={exe.status.value}, результат={exe.outcome.value}"
            breakdown.append(ControlTrustBreakdown(cid, ctrl.name, ctrl.weight, False, reason))

    fraction = counted_weight / total_weight if total_weight else 0.0
    return TrustAssessment(
        version_id=version_id,
        total_weight=total_weight,
        counted_weight=counted_weight,
        fraction=fraction,
        target_threshold=target_threshold,
        meets_target=fraction >= target_threshold,
        breakdown=breakdown,
    )


def compute_expected_trust(
    version_id: str,
    controls: dict[str, SecurityControl],
    executions: list[ControlExecution],
    pasrs: dict[str, PASR],
    target_threshold: float,
    verifications: list[VerificationSample] | None = None,
) -> TrustAssessment:
    """Ожидаемый уровень доверия новой версии (раздел 5.3, 5.2).

    Мера учитывается как обеспечивающая доверие, если выполняется одно из:

      a) выполнена фактически (EXECUTED) с результатом PASS; либо
      b) прогнозируется (PREDICTED), её ПОБП утверждён двойным решением
         (is_approved), НЕ классифицирован как «существенное изменение»,
         и — если по ней проводилась верификация выборкой (раздел 11) —
         результат верификации подтвердил соответствие.

    Мера, чей ПОБП отклонён, не заполнен как следует или провалил
    верификацию, в ожидаемый уровень доверия не засчитывается — она
    должна быть выполнена фактически (это и есть основной механизм,
    которым стандарт не позволяет прогнозированию подменить безопасность).
    """

    verifications = verifications or []
    by_control = {e.control_id: e for e in executions if e.version_id == version_id}
    verif_by_control = {
        v.control_id: v for v in verifications if v.version_id == version_id
    }

    total_weight = sum(c.weight for c in controls.values())
    counted_weight = 0.0
    breakdown: list[ControlTrustBreakdown] = []

    for cid, ctrl in controls.items():
        exe = by_control.get(cid)

        if exe and exe.status == ControlStatus.EXECUTED and exe.outcome == ControlOutcome.PASS_:
            counted_weight += ctrl.weight
            breakdown.append(
                ControlTrustBreakdown(cid, ctrl.name, ctrl.weight, True, "мера выполнена заново, результат PASS")
            )
            continue

        if exe and exe.status == ControlStatus.PREDICTED and exe.pasr_id:
            pasr = pasrs.get(exe.pasr_id)
            if pasr is None:
                breakdown.append(
                    ControlTrustBreakdown(cid, ctrl.name, ctrl.weight, False, "ссылка на ПОБП не найдена")
                )
                continue
            if pasr.substantiality_label == SubstantialityLabel.SUBSTANTIAL:
                breakdown.append(
                    ControlTrustBreakdown(
                        cid, ctrl.name, ctrl.weight, False,
                        "изменение признано существенным — прогноз не засчитан (п. 7)",
                    )
                )
                continue
            if not pasr.is_approved:
                breakdown.append(
                    ControlTrustBreakdown(
                        cid, ctrl.name, ctrl.weight, False,
                        f"ПОБП не утверждён двойным решением (НСО={pasr.onf_decision.value}, "
                        f"владелец={pasr.owner_decision.value})",
                    )
                )
                continue
            if ctrl.critical and cid not in verif_by_control:
                breakdown.append(
                    ControlTrustBreakdown(
                        cid, ctrl.name, ctrl.weight, False,
                        "критическая мера требует верификации (раздел 11) перед зачётом прогноза",
                    )
                )
                continue

            verif = verif_by_control.get(cid)
            if verif and not verif.matches_expected:
                breakdown.append(
                    ControlTrustBreakdown(
                        cid, ctrl.name, ctrl.weight, False,
                        "верификация не подтвердила прогноз (п. 11.3) — требуется фактическое выполнение",
                    )
                )
                continue

            counted_weight += ctrl.weight
            note = "подтверждено верификацией" if verif else "верификация не требовалась"
            breakdown.append(
                ControlTrustBreakdown(
                    cid, ctrl.name, ctrl.weight, True,
                    f"доверие перенесено через утверждённый ПОБП ({note})",
                )
            )
            continue

        breakdown.append(ControlTrustBreakdown(cid, ctrl.name, ctrl.weight, False, "мера не выполнена и не прогнозируется"))

    fraction = counted_weight / total_weight if total_weight else 0.0
    return TrustAssessment(
        version_id=version_id,
        total_weight=total_weight,
        counted_weight=counted_weight,
        fraction=fraction,
        target_threshold=target_threshold,
        meets_target=fraction >= target_threshold,
        breakdown=breakdown,
    )
