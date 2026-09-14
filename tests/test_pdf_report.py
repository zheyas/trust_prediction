"""Тесты PDF-отчёта (pdf_report.py).

Скачивание PDF — единственная часть программы, которая требует
дополнительной библиотеки (fpdf2, см. requirements.txt). Эти тесты
проверяют оба случая: библиотека не установлена (ясная, дружелюбная
ошибка вместо трассировки) и, если установлена — что PDF действительно
формируется (валидный заголовок файла %PDF, ненулевой размер)."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trust_prediction.demo import run as run_demo
from trust_prediction.pdf_report import PdfDependencyError, build_report_pdf
from trust_prediction.storage import Repository

try:
    import fpdf  # noqa: F401
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


class TestPdfReport(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        run_demo(Path(self.tmp.name) / "demo_run")
        self.repo = Repository(Path(self.tmp.name) / "demo_run" / "project.json")
        # версия "1.1" — вторая созданная в demo.py
        self.version_id = sorted(self.repo.versions.values(), key=lambda v: v.created_at)[-1].id

    def tearDown(self):
        self.tmp.cleanup()

    @unittest.skipIf(HAS_FPDF, "проверяем путь \"библиотека не установлена\" — fpdf2 здесь есть, пропускаем")
    def test_clear_error_when_fpdf_missing(self):
        with self.assertRaises(PdfDependencyError) as ctx:
            build_report_pdf(self.repo, self.version_id)
        self.assertIn("pip install", str(ctx.exception))

    @unittest.skipUnless(HAS_FPDF, "fpdf2 не установлена в этом окружении — см. requirements.txt")
    def test_pdf_is_generated_with_valid_header(self):
        pdf_bytes = build_report_pdf(self.repo, self.version_id)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 2000)


if __name__ == "__main__":
    unittest.main()
