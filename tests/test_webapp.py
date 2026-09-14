"""Дымовые тесты локального веб-интерфейса (webapp.py): поднимаем реальный
HTTP-сервер на свободном порту, прогоняем весь процесс через JSON API (то
же самое, что делает фронтенд), проверяем отдачу статики и файлов."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory

from trust_prediction.webapp import build_server


class TestWebapp(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        project_path = Path(self.tmp.name) / "project.json"
        self.httpd = build_server(project_path, port=0)  # port=0 -> ОС выберет свободный порт
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return resp.status, resp.read()

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                      headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_static_index_served(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<title>", body)
        self.assertIn("Прогнозирование доверия".encode("utf-8"), body)

    def test_static_assets_served(self):
        status, body = self._get("/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"loadAll", body)
        status, body = self._get("/style.css")
        self.assertEqual(status, 200)
        self.assertIn(b"--accent", body)

    def test_unknown_static_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/no-such-file.xyz")
        self.assertEqual(ctx.exception.code, 404)

    def test_state_empty_before_application_created(self):
        status, body = self._get("/api/state")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIsNone(data["application"])
        self.assertEqual(data["controls"], [])

    def test_raci_endpoint(self):
        status, body = self._get("/api/raci")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["steps"]), 10)
        self.assertTrue(data["actors"])

    def test_full_workflow_via_api(self):
        # приложение
        status, data = self._post("/api/application", {"name": "Тестовое приложение", "owner": "Тест"})
        self.assertEqual(status, 200)
        self.assertEqual(data["application"]["name"], "Тестовое приложение")

        # мера
        status, data = self._post("/api/controls", {"name": "SAST", "category": "code", "weight": 1.0, "critical": True})
        self.assertEqual(status, 200)
        control_id = data["controls"][0]["id"]

        # политика
        status, data = self._post("/api/policy", {"policy": "conditional", "actor": "НСО"})
        self.assertEqual(status, 200)
        self.assertEqual(data["policy"], "conditional")

        # эталонная версия + фактическое выполнение
        status, data = self._post("/api/versions", {"label": "1.0", "target": 0.9})
        self.assertEqual(status, 200)
        v1 = [v for v in data["versions"] if v["label"] == "1.0"][0]

        status, data = self._post(f"/api/versions/{v1['id']}/execute", {
            "control_id": control_id, "outcome": "pass", "evidence": "отчёт SAST", "by": "Команда",
        })
        self.assertEqual(status, 200)
        v1_after = [v for v in data["state"]["versions"] if v["id"] == v1["id"]][0]
        self.assertEqual(v1_after["trust"]["fraction"], 1.0)
        self.assertTrue(v1_after["trust"]["meets_target"])

        # производная версия с несущественным изменением
        status, data = self._post("/api/versions", {"label": "1.1", "parent": v1["id"], "target": 0.85})
        self.assertEqual(status, 200)
        v2 = [v for v in data["versions"] if v["label"] == "1.1"][0]

        status, data = self._post(f"/api/versions/{v2['id']}/changes", {
            "description": "Мелкое конфигурационное изменение", "category": "configuration",
            "controls": [control_id], "impact": 0.1,
        })
        self.assertEqual(status, 200)

        status, data = self._post(f"/api/versions/{v2['id']}/analyze", {"actor": "Эксперт"})
        self.assertEqual(status, 200)
        self.assertEqual(data["recommendations"][control_id]["label"], "not_substantial")

        # ПОБП
        status, data = self._post("/api/pasr", {
            "version_id": v2["id"], "control_id": control_id,
            "initiator": "Команда", "onf": "НСО", "owner": "Владелец",
            "circumstances": "тест", "rationale": "тест", "criteria": "тест",
        })
        self.assertEqual(status, 200)
        pasr_id = data["state"]["versions"][-1]["pasrs"][0]["id"]

        # двойное утверждение
        status, data = self._post(f"/api/pasr/{pasr_id}/decide", {"party": "onf", "decision": "approved", "actor": "НСО"})
        self.assertEqual(status, 200)
        status, data = self._post(f"/api/pasr/{pasr_id}/decide", {"party": "owner", "decision": "approved", "actor": "Владелец"})
        self.assertEqual(status, 200)
        v2_state = [v for v in data["state"]["versions"] if v["id"] == v2["id"]][0]
        self.assertTrue(v2_state["pasrs"][0]["is_approved"])

        # верификация, аудит, оценка
        status, data = self._post(f"/api/versions/{v2['id']}/verify", {"actor": "Аудитор", "sampling_rate": 1.0})
        self.assertEqual(status, 200)
        status, data = self._post(f"/api/versions/{v2['id']}/audit", {"actor": "Аудитор"})
        self.assertEqual(status, 200)
        self.assertIn(data["summary"]["verdict"], ("ПРИНЯТО", "ТРЕБУЕТ ДОРАБОТКИ"))
        status, data = self._post(f"/api/versions/{v2['id']}/assess", {"actor": "Аудитор"})
        self.assertEqual(status, 200)

        # отчёт
        status, body = self._get(f"/api/versions/{v2['id']}/report")
        self.assertEqual(status, 200)
        report = json.loads(body)
        self.assertIn("Отчёт об ожидаемом уровне доверия", report["markdown"])

        status, body = self._get(f"/api/versions/{v2['id']}/report?download=1")
        self.assertEqual(status, 200)
        self.assertIn("Отчёт об ожидаемом уровне доверия", body.decode("utf-8"))

    def test_forbidden_policy_blocks_pasr_via_api(self):
        self._post("/api/application", {"name": "A", "owner": "O"})
        status, data = self._post("/api/controls", {"name": "SAST"})
        control_id = data["controls"][0]["id"]
        self._post("/api/policy", {"policy": "forbidden", "actor": "НСО"})
        status, data = self._post("/api/versions", {"label": "1.0", "target": 0.9})
        v1 = data["versions"][0]
        self._post(f"/api/versions/{v1['id']}/execute", {"control_id": control_id, "outcome": "pass", "evidence": "e", "by": "b"})
        status, data = self._post("/api/versions", {"label": "1.1", "parent": v1["id"], "target": 0.9})
        v2 = [v for v in data["versions"] if v["label"] == "1.1"][0]

        status, data = self._post("/api/pasr", {
            "version_id": v2["id"], "control_id": control_id,
            "initiator": "Команда", "onf": "НСО", "owner": "Владелец",
            "circumstances": "тест", "rationale": "тест", "criteria": "тест",
        })
        self.assertEqual(status, 409)
        self.assertIn("error", data)

    def test_demo_and_switch(self):
        status, data = self._post("/api/demo", {})
        self.assertEqual(status, 200)
        self.assertEqual(data["active_project"], "demo")
        self.assertIsNotNone(data["application"])

        status, data = self._post("/api/switch", {"which": "own"})
        self.assertEqual(status, 200)
        self.assertEqual(data["active_project"], "own")
        self.assertIsNone(data["application"])

        status, data = self._post("/api/switch", {"which": "demo"})
        self.assertEqual(status, 200)
        self.assertEqual(data["active_project"], "demo")

    def test_export_downloads_raw_project_json(self):
        self._post("/api/application", {"name": "A", "owner": "O"})
        status, body = self._get("/api/export")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["application"]["name"], "A")


if __name__ == "__main__":
    unittest.main()
