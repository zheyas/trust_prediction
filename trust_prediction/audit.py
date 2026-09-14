"""Аудит и верификация ПОБП (ГОСТ Р ИСО/МЭК 27034-7-2020, разделы 10-11).

Аудит (раздел 10) проверяет:
  * соответствие фактических данных об уровне доверия требованиям (10.2);
  * наличие и соответствие ПОБП методологии организации (10.3);
  * качество формы и содержания самого ПОБП (10.4) — см. PASR.has_all_required_components.

Верификация (раздел 11) может включать повторное выполнение отдельных
ранее выполненных мер на неизменных механизмах с использованием
статистической или основанной на риске выборки (11.2), чтобы сопоставить
фактические и ожидаемые результаты (11.3). Если среда для повторного
выполнения недоступна — аудитор принимает ПОБП на основе иных
доказательств либо запрашивает альтернативные свидетельства (11.4).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .models import ControlOutcome, PASR, VerificationSample


@dataclass
class AuditFinding:
    pasr_id: str
    control_id: str
    quality_ok: bool
    issues: list[str] = field(default_factory=list)


def select_verification_sample(
    pasrs: list[PASR],
    critical_control_ids: set[str],
    sampling_rate: float = 0.34,
    rng_seed: int | None = None,
) -> list[PASR]:
    """Отбор ПОБП для верификации выборочным повторным выполнением (11.2).

    Выборка основана на риске (risk-based sampling): все ПОБП, относящиеся
    к критическим мерам, отбираются всегда; из оставшихся случайным
    образом отбирается доля sampling_rate (статистическая выборка).
    """

    approved = [p for p in pasrs if p.is_approved]
    critical = [p for p in approved if p.control_id in critical_control_ids]
    rest = [p for p in approved if p.control_id not in critical_control_ids]

    rng = random.Random(rng_seed)
    k = round(len(rest) * sampling_rate)
    sampled_rest = rng.sample(rest, k) if k > 0 else []

    return critical + sampled_rest


def verify_pasr(
    pasr: PASR,
    reexecution_outcome: ControlOutcome,
    expected_outcome: ControlOutcome = ControlOutcome.PASS_,
    notes: str = "",
) -> VerificationSample:
    """Сопоставляет результат повторного выполнения меры с ожидаемым
    результатом (п. 11.3: при повторном выполнении выборочных мер
    результаты должны совпадать с результатами исходного выполнения)."""

    matches = reexecution_outcome == expected_outcome
    return VerificationSample(
        version_id=pasr.version_id,
        control_id=pasr.control_id,
        pasr_id=pasr.id,
        reexecution_outcome=reexecution_outcome,
        matches_expected=matches,
        notes=notes or ("совпадает с ожидаемым результатом" if matches else "расхождение с ожидаемым результатом"),
    )


def audit_pasr_quality(pasr: PASR) -> AuditFinding:
    issues: list[str] = []
    if not pasr.has_all_required_components():
        issues.append("не заполнены все шесть обязательных компонентов ПОБП (п. 9.2)")
    if pasr.onf_decision.value == "pending" or pasr.owner_decision.value == "pending":
        issues.append("утверждение не завершено (требуется решение обеих сторон, п. 5.5)")
    if pasr.substantiality_label and pasr.substantiality_label.value == "substantial":
        issues.append("изменение классифицировано как существенное — использование ПОБП под вопросом (раздел 7)")
    return AuditFinding(pasr_id=pasr.id, control_id=pasr.control_id, quality_ok=not issues, issues=issues)


def audit_summary(pasrs: list[PASR], verifications: list[VerificationSample]) -> dict:
    findings = [audit_pasr_quality(p) for p in pasrs]
    verified_ok = sum(1 for v in verifications if v.matches_expected)
    verified_fail = sum(1 for v in verifications if not v.matches_expected)
    return {
        "pasr_total": len(pasrs),
        "pasr_quality_ok": sum(1 for f in findings if f.quality_ok),
        "pasr_quality_issues": sum(1 for f in findings if not f.quality_ok),
        "verification_total": len(verifications),
        "verification_matches": verified_ok,
        "verification_mismatches": verified_fail,
        "findings": findings,
        "verdict": "ПРИНЯТО" if all(f.quality_ok for f in findings) and verified_fail == 0 else "ТРЕБУЕТ ДОРАБОТКИ",
    }
