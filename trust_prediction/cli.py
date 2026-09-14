"""Интерфейс командной строки для автоматизации прогнозирования доверия
приложения по ГОСТ Р ИСО/МЭК 27034-7-2020.

Запуск:
    python -m trust_prediction.cli --help
    python -m trust_prediction.cli demo               # сквозной демонстрационный сценарий
    python -m trust_prediction.cli status --project data/project.json --version <id>

Все состояние проекта хранится в одном JSON-файле (по умолчанию
data/project.json), см. storage.Repository.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import raci
from .models import ApprovalDecision, ChangeCategory, ControlOutcome, PredictionPolicy
from .report import build_report, save_report
from .storage import Repository
from .workflow import TrustPredictionWorkflow, WorkflowError


def _repo(args) -> Repository:
    return Repository(args.project)


def cmd_init(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    app = wf.init_application(args.app, args.owner)
    print(f"Приложение создано: {app.name} (id={app.id}), владелец={app.owner}")


def cmd_add_control(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    ctrl = wf.add_control(args.name, args.category, args.weight, args.critical, args.description or "")
    print(f"Мера (МОБП) добавлена: {ctrl.name} (id={ctrl.id}), вес={ctrl.weight}, критическая={ctrl.critical}")


def cmd_new_version(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    ver = wf.new_version(args.label, args.parent, args.target)
    print(f"Версия создана: {ver.label} (id={ver.id}), эталон={args.parent}, целевой уровень={args.target*100:.0f}%")


def cmd_add_change(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    controls = args.controls.split(",") if args.controls else []
    ch = wf.add_change(args.version, args.desc, ChangeCategory(args.category), controls, args.impact, args.notes or "")
    print(f"Изменение добавлено: {ch.description} (id={ch.id}), категория={args.category}, влияние={args.impact}")


def cmd_record_reference(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    exe = wf.record_reference_execution(args.version, args.control, ControlOutcome(args.outcome), args.evidence, args.by)
    print(f"Зафиксировано выполнение эталонной меры {args.control}: {exe.outcome.value}")


def cmd_set_policy(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    res = wf.step1_set_policy(PredictionPolicy(args.policy), args.actor, args.substantial, args.borderline)
    print(res.message)


def cmd_analyze(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    res = wf.step3_risk_analysis(args.version, args.actor)
    print(res.message)
    for cid, (label, score) in res.payload["control_recommendations"].items():
        name = repo.controls[cid].name
        if label == "not_affected":
            continue
        print(f"  - {name}: {label} (score={score})")


def cmd_propose_pasr(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    try:
        res = wf.step4_prepare_pasr(
            args.version, args.control, args.initiator, args.onf, args.owner,
            args.circumstances, args.rationale, args.criteria,
        )
    except WorkflowError as e:
        print(f"ОТКАЗ: {e}", file=sys.stderr)
        sys.exit(1)
    print(res.message)


def cmd_approve(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    try:
        res = wf.step6_approve(args.pasr, args.party, ApprovalDecision(args.decision), args.actor, args.justification or "")
    except WorkflowError as e:
        print(f"ОТКАЗ: {e}", file=sys.stderr)
        sys.exit(1)
    print(res.message)


def cmd_execute(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    res = wf.step7_execute_control(args.version, args.control, ControlOutcome(args.outcome), args.evidence, args.by)
    print(res.message)


def cmd_verify(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    mismatch = args.mismatch.split(",") if args.mismatch else None
    res = wf.step8_verify(args.version, args.actor, args.sampling_rate, args.seed, mismatch)
    print(res.message)


def cmd_audit(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    res = wf.step9_audit(args.version, args.actor)
    print(res.message)


def cmd_assess(args):
    repo = _repo(args)
    wf = TrustPredictionWorkflow(repo)
    res = wf.step10_assess(args.version, args.actor)
    print(res.message)


def cmd_report(args):
    repo = _repo(args)
    out = args.out or "report.md"
    save_report(repo, args.version, out)
    print(f"Отчёт сохранён: {out}")


def cmd_status(args):
    repo = _repo(args)
    print(build_report(repo, args.version))


def cmd_raci(_args):
    print(raci.render_matrix_text())


def cmd_demo(args):
    from . import demo as demo_mod
    demo_mod.run(Path(args.out_dir))


def cmd_web(args):
    from .webapp import run_server
    run_server(args.project, args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trust_prediction",
        description="Автоматизация прогнозирования доверия приложения по ГОСТ Р ИСО/МЭК 27034-7-2020",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--project", default="data/project.json", help="путь к файлу состояния проекта (JSON)")

    sp = sub.add_parser("init", help="создать приложение")
    add_common(sp)
    sp.add_argument("--app", required=True)
    sp.add_argument("--owner", required=True)
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("add-control", help="добавить меру обеспечения безопасности (МОБП)")
    add_common(sp)
    sp.add_argument("--name", required=True)
    sp.add_argument("--category", default="general")
    sp.add_argument("--weight", type=float, default=1.0)
    sp.add_argument("--critical", action="store_true")
    sp.add_argument("--description", default="")
    sp.set_defaults(func=cmd_add_control)

    sp = sub.add_parser("new-version", help="создать версию приложения")
    add_common(sp)
    sp.add_argument("--label", required=True)
    sp.add_argument("--parent", default=None, help="id эталонной (родительской) версии")
    sp.add_argument("--target", type=float, default=0.9, help="целевой уровень доверия, 0..1")
    sp.set_defaults(func=cmd_new_version)

    sp = sub.add_parser("add-change", help="добавить изменение к версии (для анализа существенности)")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--desc", required=True)
    sp.add_argument("--category", required=True, choices=[c.value for c in ChangeCategory])
    sp.add_argument("--controls", default="", help="id мер через запятую, на которые влияет изменение")
    sp.add_argument("--impact", type=float, default=0.5, help="экспертная оценка влияния на риск, 0..1")
    sp.add_argument("--notes", default="")
    sp.set_defaults(func=cmd_add_change)

    sp = sub.add_parser("record-reference", help="зафиксировать фактическое выполнение МОБП для эталонной версии")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--control", required=True)
    sp.add_argument("--outcome", required=True, choices=["pass", "fail"])
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--by", required=True)
    sp.set_defaults(func=cmd_record_reference)

    sp = sub.add_parser("set-policy", help="шаг 1: НСО задаёт методологию прогнозирования")
    add_common(sp)
    sp.add_argument("--policy", required=True, choices=[p.value for p in PredictionPolicy])
    sp.add_argument("--actor", required=True)
    sp.add_argument("--substantial", type=float, default=0.65)
    sp.add_argument("--borderline", type=float, default=0.35)
    sp.set_defaults(func=cmd_set_policy)

    sp = sub.add_parser("analyze", help="шаг 3: анализ рисков новой версии")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--actor", required=True)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("propose-pasr", help="шаг 4: подготовка ПОБП")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--control", required=True)
    sp.add_argument("--initiator", required=True)
    sp.add_argument("--onf", required=True, help="представитель группы НСО")
    sp.add_argument("--owner", required=True, help="владелец приложения")
    sp.add_argument("--circumstances", required=True)
    sp.add_argument("--rationale", required=True)
    sp.add_argument("--criteria", required=True)
    sp.set_defaults(func=cmd_propose_pasr)

    sp = sub.add_parser("approve", help="шаг 6: утверждение прогноза (двойное)")
    add_common(sp)
    sp.add_argument("--pasr", required=True)
    sp.add_argument("--party", required=True, choices=["onf", "owner"])
    sp.add_argument("--decision", required=True, choices=["approved", "rejected"])
    sp.add_argument("--actor", required=True)
    sp.add_argument("--justification", default="")
    sp.set_defaults(func=cmd_approve)

    sp = sub.add_parser("execute", help="шаг 7: выполнение меры фактически")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--control", required=True)
    sp.add_argument("--outcome", required=True, choices=["pass", "fail"])
    sp.add_argument("--evidence", required=True)
    sp.add_argument("--by", required=True)
    sp.set_defaults(func=cmd_execute)

    sp = sub.add_parser("verify", help="шаг 8: верификация выборкой")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--actor", required=True)
    sp.add_argument("--sampling-rate", type=float, default=0.34)
    sp.add_argument("--seed", type=int, default=42)
    sp.add_argument("--mismatch", default="", help="id мер через запятую, для которых смоделировать расхождение")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("audit", help="шаг 9: аудит ПОБП и фактического уровня доверия")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--actor", required=True)
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("assess", help="шаг 10: расчёт ожидаемого уровня доверия")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--actor", required=True)
    sp.set_defaults(func=cmd_assess)

    sp = sub.add_parser("report", help="сформировать полный отчёт (раздел 13) и сохранить в файл")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("status", help="вывести отчёт в консоль без сохранения")
    add_common(sp)
    sp.add_argument("--version", required=True)
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("raci", help="вывести матрицу RACI процесса")
    sp.set_defaults(func=cmd_raci)

    sp = sub.add_parser("demo", help="запустить сквозной демонстрационный сценарий")
    sp.add_argument("--out-dir", default="demo_run")
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("web", help="запустить веб-интерфейс (HTML/CSS/JS) в браузере")
    add_common(sp)
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    sp.set_defaults(func=cmd_web)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
