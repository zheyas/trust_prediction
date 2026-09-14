"""Построение и утверждение ПОБП — прогнозного обоснования безопасности
приложения (ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 9).

Ключевое процедурное требование (п. 5.5): утверждение прогноза требует
ДВОЙНОГО одобрения — со стороны группы НСО и со стороны владельца
приложения; при этом ни одна из сторон не может принудить другую к
согласию. В программе это реализовано как два независимых решения
(onf_decision, owner_decision) — ПОБП считается утверждённым только
когда оба они равны APPROVED (см. PASR.is_approved в models.py).
"""

from __future__ import annotations

from .models import ApprovalDecision, PASR


def build_pasr(
    version_id: str,
    control_id: str,
    initiator: str,
    onf_actor: str,
    app_owner_actor: str,
    circumstances: str,
    rationale: str,
    original_execution_ref: str,
    criteria: str,
    identifiers: str | None = None,
) -> PASR:
    """Формирует проект ПОБП с шестью обязательными компонентами (п. 9.2):
    идентификаторы; действующие лица; обстоятельства; обоснование;
    результаты выполнения исходных мер; критерии достаточности."""

    ids = identifiers or f"version={version_id}; control={control_id}"
    return PASR(
        version_id=version_id,
        control_id=control_id,
        identifiers=ids,
        actors={
            "initiator": initiator,
            "onf_group": onf_actor,
            "app_owner": app_owner_actor,
        },
        circumstances=circumstances,
        rationale=rationale,
        original_execution_ref=original_execution_ref,
        criteria=criteria,
    )


def decide(pasr: PASR, party: str, decision: ApprovalDecision, justification: str = "") -> PASR:
    """Фиксирует независимое решение одной из двух утверждающих сторон.

    party: "onf" | "owner"
    """
    if party not in ("onf", "owner"):
        raise ValueError('party должен быть "onf" или "owner"')

    if party == "onf":
        pasr.onf_decision = decision
        pasr.onf_justification = justification
    else:
        pasr.owner_decision = decision
        pasr.owner_justification = justification
    return pasr


def render_pasr_text(pasr: PASR, control_name: str = "") -> str:
    lines = [
        f"ПОБП {pasr.id}" + (f" — мера «{control_name}»" if control_name else ""),
        f"  1. Идентификаторы:            {pasr.identifiers}",
        f"  2. Действующие лица:          инициатор={pasr.actors.get('initiator')}, "
        f"НСО={pasr.actors.get('onf_group')}, владелец={pasr.actors.get('app_owner')}",
        f"  3. Обстоятельства прогноза:   {pasr.circumstances}",
        f"  4. Обоснование:               {pasr.rationale}",
        f"  5. Результаты исходных МОБП:  {pasr.original_execution_ref}",
        f"  6. Критерии достаточности:    {pasr.criteria}",
    ]
    if pasr.substantiality_label:
        lines.append(
            f"  Существенность изменений:    {pasr.substantiality_label.value} "
            f"(score={pasr.substantiality_score})"
        )
    lines.append(
        f"  Утверждение: НСО={pasr.onf_decision.value}, "
        f"владелец={pasr.owner_decision.value}  ->  "
        f"{'УТВЕРЖДЕНО' if pasr.is_approved else ('ОТКЛОНЕНО' if pasr.is_rejected else 'ОЖИДАЕТ')}"
    )
    return "\n".join(lines)
