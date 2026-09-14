"""Формирование PDF-версии отчёта об ожидаемом уровне доверия
(ГОСТ Р ИСО/МЭК 27034-7-2020, раздел 13) — то же содержание, что и
report.build_report(), но в виде готового .pdf-файла для печати/архива.

Единственная зависимость всей программы: библиотека fpdf2 (устанавливается
отдельно — см. requirements.txt). Всё остальное (веб-интерфейс, CLI, ядро
логики) работает на стандартной библиотеке Python без исключений; если
fpdf2 не установлена, все функции, кроме скачивания PDF, продолжают
работать как прежде — см. PdfDependencyError ниже.

Кириллица требует TTF-шрифта с поддержкой Unicode (встроенные шрифты
fpdf2/PDF — Helvetica/Times/Courier — умеют только Latin-1). Поэтому в
пакет включён шрифт DejaVu Sans (trust_prediction/assets/) — свободная
гарнитура с разрешённым свободным распространением и встраиванием в
документы (см. assets/LICENSE_DEJAVU.txt).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import pasr as pasr_mod
from . import raci
from .audit import audit_summary
from .models import ApplicationVersion, SubstantialityLabel
from .storage import Repository
from .trust import TrustAssessment, compute_actual_trust, compute_expected_trust

ASSETS_DIR = Path(__file__).parent / "assets"
FONT_REGULAR = ASSETS_DIR / "DejaVuSans.ttf"
FONT_BOLD = ASSETS_DIR / "DejaVuSans-Bold.ttf"

# Палитра — та же, что в веб-интерфейсе (style.css), чтобы PDF и веб
# выглядели как одна система.
COLOR_ACCENT = (13, 148, 136)     # --accent
COLOR_ACCENT_DARK = (15, 118, 110)
COLOR_TEXT = (30, 41, 59)         # --text
COLOR_MUTED = (100, 116, 139)     # --text-muted
COLOR_FAINT = (148, 163, 184)     # --text-faint
COLOR_SUCCESS = (22, 163, 74)     # --success
COLOR_DANGER = (220, 38, 38)      # --danger
COLOR_WARNING = (217, 119, 6)     # --warning
COLOR_BORDER = (226, 232, 240)    # --border
COLOR_SURFACE_ALT = (248, 250, 252)  # --surface-alt


class PdfDependencyError(RuntimeError):
    """fpdf2 не установлена — скачивание PDF недоступно, пока пользователь
    не выполнит `pip install -r requirements.txt` (или `pip install fpdf2`)
    в своём виртуальном окружении."""


def _require_fpdf():
    try:
        from fpdf import FPDF  # noqa: F401
    except ImportError as e:
        raise PdfDependencyError(
            "Для скачивания PDF-отчёта требуется библиотека fpdf2, которая не установлена. "
            "Выполните в терминале, в папке проекта: "
            ".venv/bin/pip install -r requirements.txt   (или: .venv/bin/pip install fpdf2)  "
            "— после этого перезапустите веб-интерфейс."
        ) from e
    if not FONT_REGULAR.exists() or not FONT_BOLD.exists():
        raise PdfDependencyError(
            f"Не найден шрифт для PDF ({FONT_REGULAR.name}) — папка "
            f"trust_prediction/assets/ повреждена или отсутствует."
        )


def build_report_pdf(repo: Repository, version_id: str) -> bytes:
    """Формирует PDF-отчёт для версии `version_id` и возвращает его байты.

    Поднимает PdfDependencyError, если fpdf2 не установлена — вызывающий
    код (webapp.py / cli.py) должен показать пользователю понятное
    сообщение, а не падать с трассировкой.
    """
    _require_fpdf()
    from fpdf import FPDF

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

    class ReportPDF(FPDF):
        def header(self):  # шапка на каждой странице, кроме первой обложки
            if self.page_no() == 1:
                return
            self.set_font("DejaVu", "B", 9)
            self.set_text_color(*COLOR_FAINT)
            self.set_y(8)
            self.cell(0, 6, "Отчёт об ожидаемом уровне доверия — ГОСТ Р ИСО/МЭК 27034-7-2020", align="L")
            self.set_draw_color(*COLOR_BORDER)
            self.set_line_width(0.3)
            self.line(15, 15, self.w - 15, 15)
            self.set_y(20)

        def footer(self):
            self.set_y(-15)
            self.set_font("DejaVu", "", 8)
            self.set_text_color(*COLOR_FAINT)
            self.cell(0, 10, f"Стр. {self.page_no()} / {{nb}}", align="C")

    pdf = ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(left=18, top=18, right=18)
    pdf.add_font("DejaVu", "", str(FONT_REGULAR))
    pdf.add_font("DejaVu", "B", str(FONT_BOLD))
    pdf.add_page()

    usable_w = pdf.w - pdf.l_margin - pdf.r_margin

    def h1(text):
        pdf.set_font("DejaVu", "B", 20)
        pdf.set_text_color(*COLOR_TEXT)
        pdf.multi_cell(usable_w, 9, text)
        pdf.set_draw_color(*COLOR_ACCENT)
        pdf.set_line_width(0.8)
        y = pdf.get_y() + 1
        pdf.line(pdf.l_margin, y, pdf.l_margin + 40, y)
        pdf.ln(6)

    def h2(text):
        pdf.ln(3)
        pdf.set_font("DejaVu", "B", 13.5)
        pdf.set_text_color(*COLOR_ACCENT_DARK)
        pdf.multi_cell(usable_w, 7.5, text)
        pdf.ln(1)

    def h3(text):
        pdf.set_font("DejaVu", "B", 11)
        pdf.set_text_color(*COLOR_TEXT)
        pdf.multi_cell(usable_w, 6.5, text)

    def p(text, size=10.5, color=COLOR_TEXT, style=""):
        pdf.set_font("DejaVu", style, size)
        pdf.set_text_color(*color)
        pdf.multi_cell(usable_w, 5.8, text)

    def kv(label, value, value_color=COLOR_TEXT, size=10.5):
        pdf.set_font("DejaVu", "B", size)
        pdf.set_text_color(*COLOR_MUTED)
        label_w = 62
        x0, y0 = pdf.get_x(), pdf.get_y()
        pdf.multi_cell(label_w, 5.8, label)
        y1 = pdf.get_y()
        pdf.set_xy(x0 + label_w, y0)
        pdf.set_font("DejaVu", "", size)
        pdf.set_text_color(*value_color)
        pdf.multi_cell(usable_w - label_w, 5.8, str(value))
        pdf.set_y(max(y1, pdf.get_y()))

    def rule():
        pdf.ln(1.5)
        pdf.set_draw_color(*COLOR_BORDER)
        pdf.set_line_width(0.2)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(3)

    def badge_color(ok: bool):
        return COLOR_SUCCESS if ok else COLOR_DANGER

    # ------------------------------------------------------------- обложка
    pdf.set_font("DejaVu", "B", 10)
    pdf.set_text_color(*COLOR_ACCENT)
    pdf.cell(0, 6, "ГОСТ Р ИСО/МЭК 27034-7-2020")
    pdf.ln(10)
    h1("Отчёт об ожидаемом уровне доверия")
    p("Информационные технологии. Безопасность приложений. Часть 7. Основы прогнозирования доверия "
      "(идентичен ISO/IEC 27034-7:2018)", size=9.5, color=COLOR_MUTED)
    pdf.ln(4)

    kv("Приложение", app.name if app else "—")
    kv("Владелец приложения", app.owner if app else "—")
    kv("Версия", f"{ver.label}  (id: {ver.id})")
    kv("Эталонная версия", ref_label)
    kv("Политика прогнозирования (НСО)", repo.policy)
    kv("Сформирован", now)
    rule()

    # ------------------------------------------------------------ 13.1 Цель
    h2("13.1 Цель")
    p(
        f"Настоящий отчёт представляет и обосновывает результаты анализа риска, использованного "
        f"при прогнозировании доверия версии «{ver.label}» приложения «{app.name if app else '—'}», "
        f"и фиксирует достигнутый ожидаемый уровень доверия в сопоставлении с целевым уровнем, "
        f"заданным владельцем приложения."
    )

    # ---------------------------------------------------- 13.2 уровни доверия
    h2("13.2 Компоненты: уровни доверия")
    if actual_ref is not None:
        kv(
            f"Фактический уровень доверия эталонной версии «{ref_label}»",
            f"{actual_ref.as_percent()}  (цель {actual_ref.target_threshold * 100:.0f}%)  — "
            f"{'достигнут' if actual_ref.meets_target else 'НЕ достигнут'}",
            value_color=badge_color(actual_ref.meets_target),
        )
    kv("Целевой уровень доверия версии", f"{ver.target_trust_threshold * 100:.0f}%")
    kv(
        "Ожидаемый уровень доверия версии",
        f"{expected.as_percent()}  —  {'ДОСТИГНУТ' if expected.meets_target else 'НЕ ДОСТИГНУТ'}",
        value_color=badge_color(expected.meets_target),
        size=12,
    )
    pdf.ln(2)

    h3("Разбивка по мерам обеспечения безопасности (МОБП)")
    pdf.ln(1)
    for b in expected.breakdown:
        mark = "ДА" if b.counted else "нет"
        pdf.set_font("DejaVu", "B", 10)
        pdf.set_text_color(*COLOR_TEXT)
        pdf.write(5.5, f"{b.control_name}  (вес {b.weight:g})  — ")
        pdf.set_font("DejaVu", "B", 10)
        pdf.set_text_color(*badge_color(b.counted))
        pdf.write(5.5, f"{mark}")
        pdf.set_text_color(*COLOR_TEXT)
        pdf.ln(5.5)
        pdf.set_font("DejaVu", "", 9.5)
        pdf.set_text_color(*COLOR_MUTED)
        pdf.multi_cell(usable_w, 5, b.reason)
        pdf.ln(0.5)
    rule()

    # ------------------------------------------------------------ ПОБП
    h2("13.2 Компоненты: прогнозные обоснования (ПОБП)")
    if not version_pasrs:
        p("Для данной версии прогнозы не использовались — все меры выполнены фактически.", color=COLOR_MUTED)
    for pasr in version_pasrs:
        ctrl_name = repo.controls[pasr.control_id].name if pasr.control_id in repo.controls else pasr.control_id
        status = "УТВЕРЖДЕНО" if pasr.is_approved else ("ОТКЛОНЕНО" if pasr.is_rejected else "ОЖИДАЕТ")
        status_color = COLOR_SUCCESS if pasr.is_approved else (COLOR_DANGER if pasr.is_rejected else COLOR_WARNING)

        h3(f"ПОБП {pasr.id} — мера «{ctrl_name}»")
        pdf.set_font("DejaVu", "B", 9.5)
        pdf.set_text_color(*status_color)
        pdf.multi_cell(usable_w, 5, status)
        pdf.ln(0.5)

        kv("1. Идентификаторы", pasr.identifiers, size=9.5)
        kv(
            "2. Действующие лица",
            f"инициатор={pasr.actors.get('initiator')}, НСО={pasr.actors.get('onf_group')}, "
            f"владелец={pasr.actors.get('app_owner')}",
            size=9.5,
        )
        kv("3. Обстоятельства", pasr.circumstances, size=9.5)
        kv("4. Обоснование", pasr.rationale, size=9.5)
        kv("5. Результаты исходных МОБП", pasr.original_execution_ref, size=9.5)
        kv("6. Критерии достаточности", pasr.criteria, size=9.5)
        if pasr.substantiality_label:
            kv("Существенность изменений", f"{pasr.substantiality_label.value} (score={pasr.substantiality_score})", size=9.5)
        kv("Утверждение", f"НСО={pasr.onf_decision.value}, владелец={pasr.owner_decision.value}", size=9.5)
        rule()

    # ------------------------------------------------------ аудит/верификация
    h2("Аудит и верификация (разделы 10-11)")
    kv("Проверено ПОБП", f"{audit['pasr_total']}  (без замечаний: {audit['pasr_quality_ok']}, с замечаниями: {audit['pasr_quality_issues']})")
    kv("Верифицировано выборкой", f"{audit['verification_total']}  (совпало: {audit['verification_matches']}, расхождений: {audit['verification_mismatches']})")
    kv("Вердикт аудита", audit["verdict"], value_color=badge_color(audit["verdict"] == "ПРИНЯТО"), size=12)
    rule()

    # ------------------------------------------------------------ история
    h2("13.3 История прогнозов и версий")
    history_versions = []
    v = ver
    seen = set()
    while v and v.id not in seen:
        history_versions.append(v)
        seen.add(v.id)
        v = repo.versions.get(v.parent_version_id) if v.parent_version_id else None
    for v in reversed(history_versions):
        v_pasrs = repo.pasrs_for_version(v.id)
        p(
            f"•  {v.label} (id {v.id}): изменений={len(v.changes)}, ПОБП={len(v_pasrs)}, "
            f"утверждено={sum(1 for pr in v_pasrs if pr.is_approved)}",
            size=9.5,
        )
    rule()

    # ------------------------------------------------------------ допущения
    h2("13.4 Допущения")
    substantial = [pr for pr in version_pasrs if pr.substantiality_label == SubstantialityLabel.SUBSTANTIAL]
    borderline = [pr for pr in version_pasrs if pr.substantiality_label == SubstantialityLabel.BORDERLINE]
    p(
        f"Оценка существенности изменений выполнена автоматизированной эвристикой (пороги: существенно "
        f"≥ {repo.substantial_threshold}, пограничное ≥ {repo.borderline_threshold}); итоговое "
        f"решение в любом случае подтверждено двойным утверждением (п. 5.5).",
        size=9.5,
    )
    p(
        f"Изменений, классифицированных как существенные: {len(substantial)}; пограничных "
        f"(требующих отдельного обоснования): {len(borderline)}.",
        size=9.5,
    )
    p(
        "Модель уровня доверия — взвешенная доля мер (МОБП) от их суммарного веса; веса и целевой порог "
        "задаются при настройке проекта и не являются частью самого стандарта.",
        size=9.5,
    )
    rule()

    # ------------------------------------------------------------ 10 шагов
    h2("Журнал процесса (десять шагов, раздел 12)")
    for i, title in enumerate(raci.STEPS, start=1):
        p(title, size=9.5, color=COLOR_MUTED)
    rule()

    # ------------------------------------------------------------ audit log
    h2("Полный журнал аудита")
    if not repo.audit_log:
        p("Журнал пуст.", color=COLOR_MUTED)
    for entry in repo.audit_log:
        pdf.set_font("DejaVu", "B", 8.5)
        pdf.set_text_color(*COLOR_FAINT)
        pdf.multi_cell(usable_w, 4.6, f"{entry.timestamp}  [{entry.step}]  {entry.actor}")
        pdf.set_font("DejaVu", "", 9.5)
        pdf.set_text_color(*COLOR_TEXT)
        pdf.multi_cell(usable_w, 5, entry.details)
        pdf.ln(1.2)

    return bytes(pdf.output())
