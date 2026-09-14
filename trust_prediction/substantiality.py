"""Оценка существенности изменений (ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 7).

Стандарт прямо указывает (п. 7.1), что закрытого перечня признаков
существенности изменения не существует: существенность определяется
результатом анализа риска в контексте конкретного приложения и его
владельца. При этом стандарт (п. 7.2) приводит методические ориентиры:

    * изменения исходного кода, требующие повторного статического
      анализа, — как правило, прогноз неприменим;
    * изменения на уровне архитектуры — могут быть совместимы с
      прогнозом при достаточном обосновании;
    * устаревание методики тестирования эталонного приложения —
      основание пересмотреть (не использовать) прежний прогноз.

Этот модуль формализует данные ориентиры в виде прозрачной, настраиваемой
эвристики, чтобы автоматизировать первичную классификацию и подготовку
проекта обоснования. Он НЕ заменяет обязательный по стандарту анализ
риска, выполняемый человеком (аналитиком/экспертом предметной области),
а структурирует его результат (analyst_risk_impact) и переводит его в
рекомендацию. Итоговое решение о применении прогноза в любом случае
проходит через обязательное двойное утверждение (см. pasr.py, п. 5.5).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ChangeCategory, ChangeItem, SubstantialityLabel

# Базовый вес категории изменения — отражает методические ориентиры п. 7.2.
# Чем выше вес, тем менее, как правило, применим перенос доверия через ПОБП.
CATEGORY_BASE_WEIGHT: dict[ChangeCategory, float] = {
    ChangeCategory.CODE: 0.75,               # повторный статический анализ, как правило, обязателен
    ChangeCategory.ARCHITECTURE: 0.40,        # допустимо при достаточном обосновании
    ChangeCategory.TEST_METHODOLOGY: 0.55,    # устаревание методики — основание для пересмотра
    ChangeCategory.CONFIGURATION: 0.30,
    ChangeCategory.OTHER: 0.35,
}

CATEGORY_GUIDANCE: dict[ChangeCategory, str] = {
    ChangeCategory.CODE: (
        "Изменения кода, требующие повторного статического анализа: "
        "согласно п. 7.2 стандарта прогноз, как правило, неприменим."
    ),
    ChangeCategory.ARCHITECTURE: (
        "Изменения на уровне архитектуры: согласно п. 7.2 могут быть "
        "совместимы с прогнозом при достаточном обосновании в ПОБП."
    ),
    ChangeCategory.TEST_METHODOLOGY: (
        "Устаревание методики тестирования эталонного приложения: "
        "согласно п. 7.2 является основанием пересмотреть прежний прогноз."
    ),
    ChangeCategory.CONFIGURATION: (
        "Конфигурационное изменение — оценивается индивидуально по влиянию на риск."
    ),
    ChangeCategory.OTHER: "Изменение вне типовых категорий — требуется экспертная оценка риска.",
}


@dataclass
class SubstantialityAssessment:
    change_id: str
    label: SubstantialityLabel
    score: float
    guidance: str
    prediction_generally_allowed: bool


def assess_change(
    change: ChangeItem,
    substantial_threshold: float = 0.65,
    borderline_threshold: float = 0.35,
) -> SubstantialityAssessment:
    """Классифицирует изменение как существенное / пограничное / несущественное.

    score = 0.6 * базовый_вес_категории + 0.4 * экспертная_оценка_риска (0..1)

    Пороговые значения настраиваются группой НСО на шаге 1 процесса
    (см. workflow.step1_set_policy) — это соответствует тому, что именно
    НСО задаёт методологию прогнозирования (раздел 5.1, 12.2 шаг 1).
    """

    base = CATEGORY_BASE_WEIGHT.get(change.category, 0.4)
    risk = max(0.0, min(1.0, change.analyst_risk_impact))
    score = round(0.6 * base + 0.4 * risk, 3)

    if score >= substantial_threshold:
        label = SubstantialityLabel.SUBSTANTIAL
        allowed = False
    elif score >= borderline_threshold:
        label = SubstantialityLabel.BORDERLINE
        allowed = True  # допустимо только при политике CONDITIONAL/UNRESTRICTED + обоснование
    else:
        label = SubstantialityLabel.NOT_SUBSTANTIAL
        allowed = True

    guidance = CATEGORY_GUIDANCE.get(change.category, "")
    return SubstantialityAssessment(
        change_id=change.id,
        label=label,
        score=score,
        guidance=guidance,
        prediction_generally_allowed=allowed,
    )


def assess_changes(
    changes: list[ChangeItem],
    substantial_threshold: float = 0.65,
    borderline_threshold: float = 0.35,
) -> list[SubstantialityAssessment]:
    return [
        assess_change(c, substantial_threshold, borderline_threshold) for c in changes
    ]


def worst_label_for_control(
    control_id: str,
    changes: list[ChangeItem],
    assessments: list[SubstantialityAssessment],
) -> SubstantialityAssessment | None:
    """Если на меру влияет несколько изменений — берётся наиболее строгая
    (наименее благоприятная для прогнозирования) оценка."""

    order = {
        SubstantialityLabel.SUBSTANTIAL: 2,
        SubstantialityLabel.BORDERLINE: 1,
        SubstantialityLabel.NOT_SUBSTANTIAL: 0,
    }
    by_id = {a.change_id: a for a in assessments}
    relevant = [
        by_id[c.id]
        for c in changes
        if control_id in c.affected_control_ids and c.id in by_id
    ]
    if not relevant:
        return None
    return max(relevant, key=lambda a: order[a.label])
