"""Сквозной демонстрационный сценарий: прогнозирование доверия версии 1.1
условного «Портала электронного документооборота» на основе эталонной
версии 1.0, с прохождением всех десяти шагов процесса (раздел 12 ГОСТ Р
ИСО/МЭК 27034-7-2020).

Запуск:
    python -m trust_prediction.cli demo
    python -m trust_prediction.demo               # то же самое напрямую
"""

from __future__ import annotations

from pathlib import Path

from .models import ApprovalDecision, ChangeCategory, ControlOutcome, PredictionPolicy
from .report import save_report
from .storage import Repository
from .workflow import TrustPredictionWorkflow, WorkflowError


def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def run(out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    project_path = out_dir / "project.json"
    if project_path.exists():
        project_path.unlink()

    repo = Repository(project_path)
    wf = TrustPredictionWorkflow(repo)

    banner("Инициализация приложения и мер обеспечения безопасности (МОБП)")
    wf.init_application("Портал электронного документооборота", "ООО «ЦифроДок»")

    sast = wf.add_control("Статический анализ кода (SAST)", category="code", weight=1.5, critical=True)
    sca = wf.add_control("Анализ состава зависимостей (SCA)", category="code", weight=1.0)
    threat = wf.add_control("Архитектурный анализ угроз (Threat modeling)", category="architecture", weight=1.2, critical=True)
    dast = wf.add_control("Динамическое тестирование (DAST)", category="test", weight=1.0)
    cfg = wf.add_control("Проверка конфигурации окружения", category="configuration", weight=0.8)
    access = wf.add_control("Ревью контроля доступа", category="access", weight=1.0, critical=True)

    for c in (sast, sca, threat, dast, cfg, access):
        print(f"  МОБП: {c.name}  (вес={c.weight}, критическая={c.critical})")

    banner("Эталонная версия 1.0 — фактический уровень доверия")
    v1 = wf.new_version("1.0", parent_version_id=None, target_trust_threshold=0.9)
    for c in (sast, sca, threat, dast, cfg, access):
        wf.record_reference_execution(v1.id, c.id, ControlOutcome.PASS_, evidence=f"отчёт проверки «{c.name}» v1.0, PASS", executed_by="Проектная команда")
        print(f"  выполнено фактически: {c.name} -> PASS")

    banner("Новая версия 1.1 — регистрация изменений (раздел 7)")
    v2 = wf.new_version("1.1", parent_version_id=v1.id, target_trust_threshold=0.85)

    wf.add_change(
        v2.id, "Рефакторинг модуля аутентификации (изменение кода)",
        ChangeCategory.CODE, [sast.id, sca.id], analyst_risk_impact=0.7,
        notes="существенная переработка проверки токенов сессии",
    )
    wf.add_change(
        v2.id, "Изменение схемы взаимодействия микросервисов",
        ChangeCategory.ARCHITECTURE, [threat.id], analyst_risk_impact=0.3,
        notes="добавлен новый внутренний API-шлюз",
    )
    wf.add_change(
        v2.id, "Переход тестового стенда DAST на новую версию инструмента",
        ChangeCategory.TEST_METHODOLOGY, [dast.id], analyst_risk_impact=0.2,
    )
    wf.add_change(
        v2.id, "Незначительное изменение параметров логирования",
        ChangeCategory.CONFIGURATION, [cfg.id], analyst_risk_impact=0.1,
    )
    for ch in v2.changes:
        print(f"  изменение: {ch.description}  [{ch.category.value}, влияние={ch.analyst_risk_impact}]")

    banner("Шаг 1 — НСО задаёт методологию прогнозирования")
    print(wf.step1_set_policy(PredictionPolicy.CONDITIONAL, actor="Группа НСО").message)

    banner("Шаг 2 — инициирование прогноза")
    print(wf.step2_initiate(v2.id, initiator="Проектная команда").message)

    banner("Шаг 3 — анализ рисков новой версии")
    res3 = wf.step3_risk_analysis(v2.id, actor="Эксперт предметной области")
    print(res3.message)
    for cid, (label, score) in res3.payload["control_recommendations"].items():
        if label == "not_affected":
            continue
        print(f"  {repo.controls[cid].name}: {label}  (score={score})")

    banner("Шаг 4 — подготовка ПОБП (для мер, где изменения НЕ существенны)")

    def try_propose(control, circumstances, rationale, criteria):
        try:
            r = wf.step4_prepare_pasr(
                v2.id, control.id, "Проектная команда", "Группа НСО", "Владелец приложения",
                circumstances, rationale, criteria,
            )
            print(f"  OK: {r.message}")
            return r.payload["pasr"]
        except WorkflowError as e:
            print(f"  ЗАБЛОКИРОВАНО ({control.name}): {e}")
            return None

    pasr_sast = try_propose(
        sast, "Код модуля аутентификации переработан", "прогноз для SAST не запрашивается", "н/д",
    )
    pasr_threat = try_propose(
        threat, "Добавлен новый внутренний API-шлюз",
        "Изменение локализовано в внутреннем периметре, внешняя поверхность атаки не изменилась; "
        "модель угроз v1.0 пересмотрена экспертом и признана применимой с оговоркой по шлюзу",
        "заключение эксперта предметной области + отсутствие новых внешних точек входа",
    )
    pasr_dast = try_propose(
        dast, "Обновлён инструмент DAST, методика тестирования не менялась по существу",
        "Набор проверок и покрытие эквивалентны предыдущей версии инструмента, "
        "смена инструмента не затрагивает тестируемую поверхность приложения",
        "сопоставление отчётов покрытия старого и нового инструмента",
    )
    pasr_cfg = try_propose(
        cfg, "Изменены только параметры уровня логирования", "изменение не влияет на периметр безопасности", "diff конфигурации приложен",
    )
    pasr_access = try_propose(
        access, "Контроль доступа не затронут изменениями версии 1.1",
        "изменений, влияющих на контроль доступа, не зарегистрировано", "отсутствие связанных изменений в реестре",
    )

    banner("Шаг 5 — согласование с владельцем приложения")
    for p, name in ((pasr_threat, "Threat modeling"), (pasr_dast, "DAST"), (pasr_cfg, "конфигурация"), (pasr_access, "контроль доступа")):
        if p:
            wf.step5_coordinate_with_owner(p.id, "Проектная команда", f"направлено на согласование владельцу ({name})")
    print("  согласование зафиксировано в журнале аудита")

    banner("Шаг 6 — утверждение прогноза (двойное, независимое)")

    def approve_both(p, onf_ok=True, owner_ok=True, owner_reason=""):
        if p is None:
            return
        r1 = wf.step6_approve(p.id, "onf", ApprovalDecision.APPROVED if onf_ok else ApprovalDecision.REJECTED, "Группа НСО", "проверено методологией НСО")
        print(f"  {r1.message}")
        r2 = wf.step6_approve(
            p.id, "owner",
            ApprovalDecision.APPROVED if owner_ok else ApprovalDecision.REJECTED,
            "Владелец приложения", owner_reason or "обоснование признано достаточным",
        )
        print(f"  {r2.message}")

    approve_both(pasr_threat)
    approve_both(pasr_cfg)
    approve_both(pasr_access)
    # Демонстрация отказа: владелец приложения не принимает обоснование по DAST —
    # мера возвращается в план и должна быть выполнена фактически (шаг 7).
    approve_both(pasr_dast, owner_ok=False, owner_reason="аргументации о полной эквивалентности покрытия недостаточно")

    banner("Шаг 7 — выполнение оставшихся МОБП фактически")
    print(wf.step7_execute_control(v2.id, sast.id, ControlOutcome.PASS_, "повторный SAST v1.1, PASS", "Проектная команда").message)
    print(wf.step7_execute_control(v2.id, sca.id, ControlOutcome.PASS_, "повторный SCA v1.1, PASS", "Проектная команда").message)
    print(wf.step7_execute_control(v2.id, dast.id, ControlOutcome.PASS_, "DAST на новом стенде v1.1, PASS", "Проектная команда").message)

    banner("Шаг 8 — верификация выборкой (раздел 11)")
    res8 = wf.step8_verify(v2.id, "Аудитор", sampling_rate=0.5, rng_seed=42)
    print(res8.message)
    for v in res8.payload["verifications"]:
        name = repo.controls[v.control_id].name
        print(f"  верифицировано: {name} -> {v.reexecution_outcome.value} "
              f"({'совпадает' if v.matches_expected else 'РАСХОЖДЕНИЕ'})")

    banner("Шаг 9 — аудит ПОБП и фактического уровня доверия")
    res9 = wf.step9_audit(v2.id, "Аудитор")
    print(res9.message)

    banner("Шаг 10 — ожидаемый уровень доверия версии 1.1")
    res10 = wf.step10_assess(v2.id, "Аудитор")
    print(res10.message)
    expected = res10.payload["expected"]
    for b in expected.breakdown:
        mark = "УЧТЕНО" if b.counted else "не учтено"
        print(f"  [{mark:10}] {b.control_name} (вес {b.weight:g}) — {b.reason}")

    report_path = out_dir / "report.md"
    save_report(repo, v2.id, str(report_path))

    banner("Готово")
    print(f"Состояние проекта:  {project_path}")
    print(f"Отчёт (раздел 13):  {report_path}")


if __name__ == "__main__":
    import sys
    run(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo_run"))
