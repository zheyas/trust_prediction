"""Формирование отчёта об ожидаемом уровне доверия
(ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 13).

Согласно п. 13.1 отчёт представляет и обосновывает результаты анализа
риска, использованного при прогнозировании. Стандарт задаёт требования
к структуре отчёта, порядку отражения истории использованных прогнозов
и явной фиксации сделанных допущений (пп. 13.2-13.4). Функция ниже
формирует такой отчёт в формате Markdown на основании состояния проекта.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import pasr as pasr_mod
from . import raci
from .audit import audit_summary
from .models import ApplicationVersion, SubstantialityLabel
from .storage import Repository
from .trust import TrustAssessment, compute_actual_trust, compute_expected_trust


def _trust_table(t: TrustAssessment) -> str:
    lines = ["| Мера | Вес | Учтена | Обоснование |", "|---|---|---|---|"]
    for b in t.breakdown:
        mark = "да" if b.counted else "нет"
        lines.append(f"| {b.control_name} | {b.weight:g} | {mark} | {b.reason} |")
    return "\n".join(lines)


def build_report(repo: Repository, version_id: str) -> str:
    ver: ApplicationVersion = repo.versions[version_id]
    app = repo.application
    executions = repo.executions_for_version(version_id)
    version_pasrs = repo.pasrs_for_version(version_id)
    verifications = [v for v in repo.verifications.values() if v.version_id == version_id]

    expected = compute_expected_trust(
        version_id, repo.controls, executions, repo.pasrs, ver.target_trust_threshold, verifications
    )

    actual_ref = None
    ref_label = "—"
    if ver.parent_version_id and ver.parent_version_id in repo.versions:
        ref_ver = repo.versions[ver.parent_version_id]
        ref_label = ref_ver.label
        ref_executions = repo.executions_for_version(ver.parent_version_id)
        actual_ref = compute_actual_trust(
            ver.parent_version_id, repo.controls, ref_executions, ref_ver.target_trust_threshold
        )

    audit = audit_summary(version_pasrs, verifications)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts: list[str] = []
    parts.append(f"# Отчёт об ожидаемом уровне доверия\n")
    parts.append(f"**Стандарт:** ГОСТ Р ИСО/МЭК 27034-7-2020 «Основы прогнозирования доверия» "
                 f"(идентичен ISO/IEC 27034-7:2018)\n")
    parts.append(f"**Сформирован:** {now}\n")
    parts.append(f"**Приложение:** {app.name if app else '—'}  ·  **Владелец:** {app.owner if app else '—'}\n")
    parts.append(f"**Версия:** {ver.label}  (id: `{ver.id}`)  ·  **Эталонная версия:** {ref_label}\n")
    parts.append(f"**Политика прогнозирования (НСО):** {repo.policy}\n")

    parts.append("\n## 13.1 Цель\n")
    parts.append(
        "Настоящий отчёт представляет и обосновывает результаты анализа риска, "
        "использованного при прогнозировании доверия версии «{}» приложения «{}», "
        "и фиксирует достигнутый ожидаемый уровень доверия в сопоставлении с "
        "целевым уровнем, заданным владельцем приложения.\n".format(ver.label, app.name if app else "—")
    )

    parts.append("\n## 13.2 Компоненты: уровни доверия\n")
    if actual_ref is not None:
        parts.append(f"- Фактический уровень доверия эталонной версии «{ref_label}»: "
                      f"**{actual_ref.as_percent()}** (цель {actual_ref.target_threshold*100:.0f}%) — "
                      f"{'достигнут' if actual_ref.meets_target else 'НЕ достигнут'}\n")
    parts.append(f"- Целевой уровень доверия версии «{ver.label}»: **{ver.target_trust_threshold*100:.0f}%**\n")
    parts.append(f"- Ожидаемый уровень доверия версии «{ver.label}»: **{expected.as_percent()}** — "
                 f"{'ДОСТИГНУТ' if expected.meets_target else 'НЕ ДОСТИГНУТ'}\n")

    parts.append("\n### Разбивка по мерам обеспечения безопасности (МОБП)\n")
    parts.append(_trust_table(expected) + "\n")

    parts.append("\n## 13.2 Компоненты: прогнозные обоснования (ПОБП)\n")
    if not version_pasrs:
        parts.append("Для данной версии прогнозы не использовались — все меры выполнены фактически.\n")
    for p in version_pasrs:
        ctrl_name = repo.controls[p.control_id].name if p.control_id in repo.controls else p.control_id
        parts.append("```\n" + pasr_mod.render_pasr_text(p, ctrl_name) + "\n```\n")

    parts.append("\n## Аудит и верификация (разделы 10-11)\n")
    parts.append(f"- Проверено ПОБП: {audit['pasr_total']}, из них без замечаний: {audit['pasr_quality_ok']}, "
                 f"с замечаниями: {audit['pasr_quality_issues']}\n")
    parts.append(f"- Верифицировано выборочным повторным выполнением: {audit['verification_total']} "
                 f"(совпало: {audit['verification_matches']}, расхождений: {audit['verification_mismatches']})\n")
    parts.append(f"- **Вердикт аудита: {audit['verdict']}**\n")

    parts.append("\n## 13.3 История прогнозов и версий\n")
    history_versions = []
    v = ver
    seen = set()
    while v and v.id not in seen:
        history_versions.append(v)
        seen.add(v.id)
        v = repo.versions.get(v.parent_version_id) if v.parent_version_id else None
    for v in reversed(history_versions):
        v_pasrs = repo.pasrs_for_version(v.id)
        parts.append(f"- **{v.label}** (id `{v.id}`): изменений={len(v.changes)}, ПОБП={len(v_pasrs)}, "
                     f"утверждено={sum(1 for p in v_pasrs if p.is_approved)}\n")

    parts.append("\n## 13.4 Допущения\n")
    substantial = [p for p in version_pasrs if p.substantiality_label == SubstantialityLabel.SUBSTANTIAL]
    borderline = [p for p in version_pasrs if p.substantiality_label == SubstantialityLabel.BORDERLINE]
    parts.append(f"- Оценка существенности изменений выполнена автоматизированной эвристикой "
                 f"(пороги: существенно ≥ {repo.substantial_threshold}, пограничное ≥ {repo.borderline_threshold}); "
                 f"итоговое решение в любом случае подтверждено двойным утверждением (п. 5.5).\n")
    parts.append(f"- Изменений, классифицированных как существенные: {len(substantial)}; "
                 f"пограничных (требующих отдельного обоснования): {len(borderline)}.\n")
    parts.append("- Модель уровня доверия — взвешенная доля мер (МОБП) от их суммарного веса; "
                 "веса и целевой порог задаются при настройке проекта и не являются частью самого стандарта.\n")

    parts.append("\n## Журнал процесса (десять шагов, раздел 12)\n")
    for i, title in enumerate(raci.STEPS, start=1):
        parts.append(f"{i}. {title}\n")

    parts.append("\n## Полный журнал аудита\n")
    for entry in repo.audit_log:
        parts.append(f"- `{entry.timestamp}` [{entry.step}] {entry.actor}: {entry.details}\n")

    return "\n".join(parts)


def save_report(repo: Repository, version_id: str, out_path: str) -> str:
    text = build_report(repo, version_id)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return out_path
