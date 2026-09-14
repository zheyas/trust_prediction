"""Локальный веб-интерфейс (HTML+CSS+JS) поверх пакета trust_prediction.

Реализован без внешних зависимостей — встроенный http.server отдаёт
статические файлы (trust_prediction/static/) и обслуживает небольшой
JSON REST API, за которым стоят те же функции workflow.py/report.py/
raci.py, что использует и CLI (cli.py). Состояние проекта хранится в том
же JSON-файле (см. storage.Repository) — веб-интерфейс и CLI полностью
взаимозаменяемы и могут работать с одним и тем же файлом проекта.

Запуск:
    python main.py web --project data/project.json --port 8765
"""

from __future__ import annotations

import json
import mimetypes
import re
import threading
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, parse_qs

from . import audit as audit_mod
from . import demo as demo_mod
from . import raci
from .models import ApprovalDecision, ChangeCategory, ControlOutcome, PredictionPolicy
from .pdf_report import PdfDependencyError, build_report_pdf
from .report import build_report
from .storage import Repository
from .trust import compute_actual_trust, compute_expected_trust
from .workflow import TrustPredictionWorkflow, WorkflowError

STATIC_DIR = Path(__file__).parent / "static"

_lock = threading.RLock()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- #
# Сериализация состояния проекта в JSON, пригодный для фронтенда
# --------------------------------------------------------------------------- #

def _trust_dict(t) -> dict:
    return {
        "fraction": round(t.fraction, 4),
        "percent": t.as_percent(),
        "counted_weight": t.counted_weight,
        "total_weight": t.total_weight,
        "target_threshold": t.target_threshold,
        "meets_target": t.meets_target,
        "breakdown": [
            {
                "control_id": b.control_id,
                "control_name": b.control_name,
                "weight": b.weight,
                "counted": b.counted,
                "reason": b.reason,
            }
            for b in t.breakdown
        ],
    }


def _serialize_pasr(p, controls) -> dict:
    d = asdict(p)
    d["onf_decision"] = p.onf_decision.value
    d["owner_decision"] = p.owner_decision.value
    d["substantiality_label"] = p.substantiality_label.value if p.substantiality_label else None
    d["is_approved"] = p.is_approved
    d["is_rejected"] = p.is_rejected
    d["has_all_required_components"] = p.has_all_required_components()
    d["control_name"] = controls[p.control_id].name if p.control_id in controls else p.control_id
    return d


def _serialize_execution(e, controls) -> dict:
    d = asdict(e)
    d["status"] = e.status.value
    d["outcome"] = e.outcome.value
    d["control_name"] = controls[e.control_id].name if e.control_id in controls else e.control_id
    return d


def _serialize_verification(v) -> dict:
    d = asdict(v)
    d["reexecution_outcome"] = v.reexecution_outcome.value
    return d


def _serialize_change(c) -> dict:
    d = asdict(c)
    d["category"] = c.category.value
    return d


def state_dict(repo: Repository, active_label: str) -> dict:
    controls = repo.controls
    versions_out = []
    for ver in repo.versions.values():
        executions = repo.executions_for_version(ver.id)
        version_pasrs = repo.pasrs_for_version(ver.id)
        verifications = [v for v in repo.verifications.values() if v.version_id == ver.id]
        is_reference = ver.parent_version_id is None

        if is_reference:
            trust = compute_actual_trust(ver.id, controls, executions, ver.target_trust_threshold)
        else:
            trust = compute_expected_trust(
                ver.id, controls, executions, repo.pasrs, ver.target_trust_threshold, verifications
            )

        audit_summary = audit_mod.audit_summary(version_pasrs, verifications)

        versions_out.append(
            {
                "id": ver.id,
                "label": ver.label,
                "parent_version_id": ver.parent_version_id,
                "is_reference": is_reference,
                "created_at": ver.created_at,
                "target_trust_threshold": ver.target_trust_threshold,
                "changes": [_serialize_change(c) for c in ver.changes],
                "trust": _trust_dict(trust),
                "trust_kind": "actual" if is_reference else "expected",
                "executions": [_serialize_execution(e, controls) for e in executions],
                "pasrs": [_serialize_pasr(p, controls) for p in version_pasrs],
                "verifications": [_serialize_verification(v) for v in verifications],
                "audit_summary": {k: v for k, v in audit_summary.items() if k != "findings"},
            }
        )

    versions_out.sort(key=lambda v: v["created_at"])

    return {
        "active_project": active_label,
        "application": asdict(repo.application) if repo.application else None,
        "policy": repo.policy,
        "substantial_threshold": repo.substantial_threshold,
        "borderline_threshold": repo.borderline_threshold,
        "controls": [asdict(c) for c in repo.controls.values()],
        "versions": versions_out,
        "audit_log": [asdict(e) for e in reversed(repo.audit_log)],
    }


def raci_dict() -> dict:
    actors = list(raci.RU_ACTOR.keys())
    return {
        "steps": raci.STEPS,
        "actors": [{"key": a.value, "label": raci.RU_ACTOR[a]} for a in actors],
        "matrix": {
            str(i): {a.value: raci.role_of(i, a).value for a in actors}
            for i in range(1, len(raci.STEPS) + 1)
        },
        "role_legend": {
            "R": "Ответственность (О) — исполняет действие",
            "A": "Подотчётность (П) — утверждает результат",
            "C": "Консультирование (К) — привлекается обязательно",
            "I": "Информирование (И) — уведомляется о результате",
            "-": "Не участвует",
        },
    }


# --------------------------------------------------------------------------- #
# Обработчики API (принимают Repository + распарсенное тело запроса)
# --------------------------------------------------------------------------- #

def _require(body: dict, *fields: str) -> None:
    missing = [f for f in fields if body.get(f) in (None, "")]
    if missing:
        raise ApiError(400, f"Отсутствуют обязательные поля: {', '.join(missing)}")


def h_get_state(ctx, m, body):
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_get_raci(ctx, m, body):
    return 200, raci_dict()


def h_post_application(ctx, m, body):
    _require(body, "name", "owner")
    wf = TrustPredictionWorkflow(ctx["repo"])
    wf.init_application(body["name"], body["owner"])
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_post_control(ctx, m, body):
    _require(body, "name")
    wf = TrustPredictionWorkflow(ctx["repo"])
    wf.add_control(
        body["name"],
        body.get("category") or "general",
        float(body.get("weight", 1.0) or 1.0),
        bool(body.get("critical", False)),
        body.get("description") or "",
    )
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_post_policy(ctx, m, body):
    _require(body, "policy", "actor")
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        policy = PredictionPolicy(body["policy"])
    except ValueError:
        raise ApiError(400, f"Неизвестная политика: {body['policy']}")
    wf.step1_set_policy(
        policy,
        body["actor"],
        float(body.get("substantial", 0.65) or 0.65),
        float(body.get("borderline", 0.35) or 0.35),
    )
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_post_version(ctx, m, body):
    _require(body, "label")
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        wf.new_version(
            body["label"],
            body.get("parent") or None,
            float(body.get("target", 0.9) or 0.9),
        )
    except WorkflowError as e:
        raise ApiError(400, str(e))
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_post_change(ctx, m, body):
    version_id = m.group("id")
    _require(body, "description", "category")
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        category = ChangeCategory(body["category"])
    except ValueError:
        raise ApiError(400, f"Неизвестная категория изменения: {body['category']}")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf.add_change(
        version_id,
        body["description"],
        category,
        list(body.get("controls") or []),
        float(body.get("impact", 0.5) or 0.5),
        body.get("notes") or "",
    )
    return 200, state_dict(ctx["repo"], ctx["active_label_fn"]())


def h_post_analyze(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf = TrustPredictionWorkflow(ctx["repo"])
    actor = (body or {}).get("actor") or "Эксперт предметной области"
    res = wf.step3_risk_analysis(version_id, actor)
    recs = {
        cid: {"label": label, "score": score}
        for cid, (label, score) in res.payload["control_recommendations"].items()
    }
    return 200, {"message": res.message, "recommendations": recs, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_pasr(ctx, m, body):
    _require(
        body, "version_id", "control_id", "initiator", "onf", "owner",
        "circumstances", "rationale", "criteria",
    )
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        res = wf.step4_prepare_pasr(
            body["version_id"], body["control_id"], body["initiator"], body["onf"], body["owner"],
            body["circumstances"], body["rationale"], body["criteria"],
        )
    except WorkflowError as e:
        raise ApiError(409, str(e))
    except KeyError as e:
        raise ApiError(404, f"Не найдено: {e}")
    return 200, {"message": res.message, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_pasr_decide(ctx, m, body):
    pasr_id = m.group("id")
    _require(body, "party", "decision", "actor")
    if pasr_id not in ctx["repo"].pasrs:
        raise ApiError(404, "ПОБП не найден")
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        decision = ApprovalDecision(body["decision"])
    except ValueError:
        raise ApiError(400, f"Неизвестное решение: {body['decision']}")
    if body["party"] not in ("onf", "owner"):
        raise ApiError(400, 'party должен быть "onf" или "owner"')
    try:
        res = wf.step6_approve(pasr_id, body["party"], decision, body["actor"], body.get("justification") or "")
    except WorkflowError as e:
        raise ApiError(409, str(e))
    return 200, {"message": res.message, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_execute(ctx, m, body):
    version_id = m.group("id")
    _require(body, "control_id", "outcome", "evidence", "by")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf = TrustPredictionWorkflow(ctx["repo"])
    try:
        outcome = ControlOutcome(body["outcome"])
    except ValueError:
        raise ApiError(400, f"Неизвестный результат: {body['outcome']}")
    res = wf.step7_execute_control(version_id, body["control_id"], outcome, body["evidence"], body["by"])
    return 200, {"message": res.message, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_verify(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf = TrustPredictionWorkflow(ctx["repo"])
    actor = (body or {}).get("actor") or "Аудитор"
    sampling_rate = float((body or {}).get("sampling_rate", 0.34) or 0.34)
    seed = (body or {}).get("seed")
    seed = int(seed) if seed not in (None, "") else 42
    mismatch = list((body or {}).get("mismatch") or [])
    res = wf.step8_verify(version_id, actor, sampling_rate, seed, mismatch)
    return 200, {"message": res.message, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_audit(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf = TrustPredictionWorkflow(ctx["repo"])
    actor = (body or {}).get("actor") or "Аудитор"
    res = wf.step9_audit(version_id, actor)
    summary = dict(res.payload["summary"])
    summary["findings"] = [asdict(f) for f in summary.get("findings", [])]
    return 200, {"message": res.message, "summary": summary, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_post_assess(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    wf = TrustPredictionWorkflow(ctx["repo"])
    actor = (body or {}).get("actor") or "Аудитор"
    res = wf.step10_assess(version_id, actor)
    return 200, {"message": res.message, "state": state_dict(ctx["repo"], ctx["active_label_fn"]())}


def h_get_report(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    text = build_report(ctx["repo"], version_id)
    if ctx["query"].get("download"):
        ver = ctx["repo"].versions[version_id]
        filename = f"report_{ver.label}.md".replace(" ", "_")
        return 200, {"__raw__": True, "content_type": "text/markdown; charset=utf-8", "filename": filename, "body": text}
    return 200, {"markdown": text}


def h_get_report_pdf(ctx, m, body):
    version_id = m.group("id")
    if version_id not in ctx["repo"].versions:
        raise ApiError(404, "Версия не найдена")
    try:
        pdf_bytes = build_report_pdf(ctx["repo"], version_id)
    except PdfDependencyError as e:
        raise ApiError(501, str(e))
    ver = ctx["repo"].versions[version_id]
    filename = f"report_{ver.label}.pdf".replace(" ", "_")
    return 200, {"__raw__": True, "content_type": "application/pdf", "filename": filename, "body": pdf_bytes}


def h_get_export(ctx, m, body):
    data = json.dumps(
        json.loads(ctx["project_path_active"].read_text(encoding="utf-8"))
        if ctx["project_path_active"].exists() else {},
        ensure_ascii=False, indent=2,
    )
    return 200, {"__raw__": True, "content_type": "application/json; charset=utf-8", "filename": "project.json", "body": data}


def h_post_demo(ctx, m, body):
    demo_dir = ctx["project_path"].parent / "demo_run"
    demo_mod.run(demo_dir)
    ctx["set_active"]("demo", demo_dir / "project.json")
    # demo_mod.run() написал НОВЫЙ файл проекта уже после того, как ctx["repo"]
    # был загружен — перечитываем состояние с актуального активного пути.
    fresh_repo = Repository(ctx["active_path_fn"]())
    return 200, state_dict(fresh_repo, ctx["active_label_fn"]())


def h_post_switch(ctx, m, body):
    which = (body or {}).get("which")
    if which == "own":
        ctx["set_active"]("own", ctx["own_path"])
    elif which == "demo":
        demo_path = ctx["project_path"].parent / "demo_run" / "project.json"
        if not demo_path.exists():
            raise ApiError(404, "Демо-сценарий ещё не запускался")
        ctx["set_active"]("demo", demo_path)
    else:
        raise ApiError(400, 'which должен быть "own" или "demo"')
    fresh_repo = Repository(ctx["active_path_fn"]())
    return 200, state_dict(fresh_repo, ctx["active_label_fn"]())


ROUTES: list[tuple[str, re.Pattern, Callable]] = [
    ("GET", re.compile(r"^/api/state$"), h_get_state),
    ("GET", re.compile(r"^/api/raci$"), h_get_raci),
    ("POST", re.compile(r"^/api/application$"), h_post_application),
    ("POST", re.compile(r"^/api/controls$"), h_post_control),
    ("POST", re.compile(r"^/api/policy$"), h_post_policy),
    ("POST", re.compile(r"^/api/versions$"), h_post_version),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/changes$"), h_post_change),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/analyze$"), h_post_analyze),
    ("POST", re.compile(r"^/api/pasr$"), h_post_pasr),
    ("POST", re.compile(r"^/api/pasr/(?P<id>[\w-]+)/decide$"), h_post_pasr_decide),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/execute$"), h_post_execute),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/verify$"), h_post_verify),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/audit$"), h_post_audit),
    ("POST", re.compile(r"^/api/versions/(?P<id>[\w-]+)/assess$"), h_post_assess),
    ("GET", re.compile(r"^/api/versions/(?P<id>[\w-]+)/report$"), h_get_report),
    ("GET", re.compile(r"^/api/versions/(?P<id>[\w-]+)/report\.pdf$"), h_get_report_pdf),
    ("GET", re.compile(r"^/api/export$"), h_get_export),
    ("POST", re.compile(r"^/api/demo$"), h_post_demo),
    ("POST", re.compile(r"^/api/switch$"), h_post_switch),
]


# --------------------------------------------------------------------------- #
# HTTP-сервер
# --------------------------------------------------------------------------- #

class _State:
    """Держит путь к активному файлу проекта (свой / демо) и блокировку."""

    def __init__(self, project_path: Path):
        self.own_path = project_path
        self.active_kind = "own"
        self.active_path = project_path

    def set_active(self, kind: str, path: Path) -> None:
        self.active_kind = kind
        self.active_path = path

    @property
    def active_label(self) -> str:
        return "demo" if self.active_kind == "demo" else "own"


def make_handler(state: _State) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TrustPredictionGUI/1.0"

        def log_message(self, fmt, *args):
            pass  # тихий сервер — не засорять консоль пользователя

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_raw(self, status: int, content_type: str, filename: str | None, body) -> None:
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_file(self, path: Path) -> None:
            data = path.read_bytes()
            ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or ctype in ("application/javascript",) else ""))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                raise ApiError(400, "Некорректный JSON в теле запроса")

        def _dispatch(self, method: str) -> None:
            parsed = urlparse(self.path)
            route_path = parsed.path

            if method == "GET" and not route_path.startswith("/api/"):
                self._serve_static(route_path)
                return

            for rt_method, pattern, handler in ROUTES:
                if rt_method != method:
                    continue
                match = pattern.match(route_path)
                if not match:
                    continue
                try:
                    body = self._read_body() if method == "POST" else {}
                    query = parse_qs(parsed.query)
                    with _lock:
                        repo = Repository(state.active_path)
                        ctx = {
                            "repo": repo,
                            "project_path": state.own_path,
                            "project_path_active": state.active_path,
                            "own_path": state.own_path,
                            "active_label_fn": lambda: state.active_label,
                            "active_path_fn": lambda: state.active_path,
                            "set_active": state.set_active,
                            "query": query,
                        }
                        status, payload = handler(ctx, match, body)
                    if isinstance(payload, dict) and payload.get("__raw__"):
                        self._send_raw(status, payload["content_type"], payload.get("filename"), payload["body"])
                    else:
                        self._send_json(status, payload)
                except ApiError as e:
                    self._send_json(e.status, {"error": e.message})
                except Exception as e:  # pragma: no cover - защитный барьер
                    self._send_json(500, {"error": f"Внутренняя ошибка: {e}"})
                return

            self._send_json(404, {"error": "Маршрут не найден"})

        def _serve_static(self, route_path: str) -> None:
            if route_path == "/":
                route_path = "/index.html"
            candidate = (STATIC_DIR / route_path.lstrip("/")).resolve()
            try:
                candidate.relative_to(STATIC_DIR.resolve())
            except ValueError:
                self.send_error(403)
                return
            if not candidate.exists() or not candidate.is_file():
                self.send_error(404)
                return
            self._send_file(candidate)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def build_server(project: str | Path, port: int = 8765, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    """Создаёт (но не запускает) HTTP-сервер — удобно для тестов, которым
    нужно самим управлять жизненным циклом (serve_forever/shutdown)."""
    project_path = Path(project)
    project_path.parent.mkdir(parents=True, exist_ok=True)
    state = _State(project_path)
    handler_cls = make_handler(state)
    return ThreadingHTTPServer((host, port), handler_cls)


def run_server(project: str | Path, port: int = 8765, open_browser: bool = True, host: str = "127.0.0.1") -> None:
    httpd = build_server(project, port, host)
    url = f"http://{host}:{port}/"

    print(f"Веб-интерфейс прогнозирования доверия запущен: {url}")
    print(f"Файл проекта: {project}")
    print("Остановить сервер: Ctrl+C")

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
