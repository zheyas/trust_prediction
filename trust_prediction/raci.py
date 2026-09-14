"""Матрица ответственности RACI для десятишагового процесса осуществления
ПОБП (ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 12, по логике распределения
ролей раздела 9.5).

О — Ответственность (R, responsible) — исполняет действие
П — Подотчётность   (A, accountable) — утверждает результат
К — Консультирование (C, consulted)  — привлекается обязательно
И — Информирование  (I, informed)   — уведомляется о результате

ВАЖНО: стандарт задаёт логику и состав ролей (таблица 2 — для ПОБП,
таблица 3 — для процесса осуществления), но конкретное распределение
ролей по организации индивидуально. Приведённая ниже матрица — это
референсная конфигурация по умолчанию, соответствующая роли каждого
участника, описанной во введении и разделах 9/12 стандарта; при
необходимости её можно отредактировать под свою организацию (см.
DEFAULT_STEP_RACI ниже — это обычный словарь Python).
"""

from __future__ import annotations

from .models import ActorCategory as A
from .models import RaciRole as R

STEPS = [
    "1. НСО задаёт методологию прогнозирования",
    "2. Инициирование прогноза проектной командой",
    "3. Анализ рисков новой версии",
    "4. Подготовка ПОБП",
    "5. Согласование с владельцем приложения",
    "6. Утверждение прогноза (двойное)",
    "7. Выполнение оставшихся МОБП",
    "8. Проверка и верификация результатов",
    "9. Аудит ПОБП и фактического уровня доверия",
    "10. Формирование отчёта об ожидаемом уровне доверия",
]

# step index (1..10) -> {actor: role}
DEFAULT_STEP_RACI: dict[int, dict[A, R]] = {
    1: {A.ONF_GROUP: R.R, A.MANAGER: R.A, A.PROJECT_TEAM: R.I, A.APP_OWNER: R.I},
    2: {A.PROJECT_TEAM: R.R, A.APP_OWNER: R.A, A.ONF_GROUP: R.I},
    3: {A.PROJECT_TEAM: R.R, A.DOMAIN_EXPERT: R.C, A.APP_OWNER: R.A, A.ONF_GROUP: R.I},
    4: {A.PROJECT_TEAM: R.R, A.DOMAIN_EXPERT: R.C, A.ONF_GROUP: R.I},
    5: {A.PROJECT_TEAM: R.R, A.APP_OWNER: R.A},
    6: {A.ONF_GROUP: R.A, A.APP_OWNER: R.A, A.PROJECT_TEAM: R.I, A.ACQUIRER: R.I},
    7: {A.PROJECT_TEAM: R.R, A.APP_OWNER: R.A},
    8: {A.AUDITOR: R.R, A.PROJECT_TEAM: R.C, A.ONF_GROUP: R.I},
    9: {A.AUDITOR: R.R, A.ONF_GROUP: R.A, A.APP_OWNER: R.I},
    10: {A.AUDITOR: R.R, A.ONF_GROUP: R.A, A.APP_OWNER: R.I, A.ACQUIRER: R.I},
}

RU_ROLE = {R.R: "О", R.A: "П", R.C: "К", R.I: "И", R.NONE: "-"}
RU_ACTOR = {
    A.MANAGER: "Руководитель",
    A.ONF_GROUP: "Группа НСО",
    A.PROJECT_TEAM: "Проектная команда",
    A.DOMAIN_EXPERT: "Эксперт предметной области",
    A.AUDITOR: "Аудитор",
    A.APP_OWNER: "Владелец приложения",
    A.ACQUIRER: "Приобретающая сторона",
}


def role_of(step: int, actor: A) -> R:
    return DEFAULT_STEP_RACI.get(step, {}).get(actor, R.NONE)


def render_matrix_text() -> str:
    actors = list(A)
    col_width = max(len(t) for t in STEPS) + 2
    header = "Шаг".ljust(col_width) + "".join(RU_ACTOR[a][:3].ljust(6) for a in actors)
    lines = [header, "-" * len(header)]
    for i, title in enumerate(STEPS, start=1):
        row = title.ljust(col_width)
        row += "".join(RU_ROLE[role_of(i, a)].ljust(6) for a in actors)
        lines.append(row)
    legend = "\nО=Ответственность  П=Подотчётность  К=Консультирование  И=Информирование"
    return "\n".join(lines) + legend


def actors_required_to_approve(step: int) -> list[A]:
    """Кто на данном шаге несёт подотчётность (П) — то есть должен
    формально утвердить результат шага."""
    return [a for a, r in DEFAULT_STEP_RACI.get(step, {}).items() if r == R.A]
