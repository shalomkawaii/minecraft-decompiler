from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcdc.cli import EXIT_OK, EXIT_STRICT, main
from mcdc.reports import render_warning
from tests.helpers import CLEAN_SOURCES, OBFUSCATED_SOURCES, build_jar


def run_cli(arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_analyze_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, OBFUSCATED_SOURCES, debug=False)
            code, output, _ = run_cli(["analyze", str(jar), "--json"])
            payload = json.loads(output)
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(payload["obfuscation"]["detected"])
            self.assertEqual(payload["input"]["kind"], "library")

    def test_analyze_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, OBFUSCATED_SOURCES, debug=False)
            code, _, _ = run_cli(["analyze", str(jar), "--strict"])
            self.assertEqual(code, EXIT_STRICT)

    def test_clean_jar_is_not_strict_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, CLEAN_SOURCES)
            code, output, _ = run_cli(["analyze", str(jar), "--strict", "--json"])
            payload = json.loads(output)
            self.assertEqual(code, EXIT_OK)
            self.assertFalse(payload["obfuscation"]["detected"])

    def test_warning_text_has_no_emoji(self) -> None:
        warning = render_warning(
            {
                "detected": True,
                "level": "high",
                "confidence": 90,
                "likely_official_minecraft": False,
                "advice": ["Review this jar before running it."],
                "reasons": [{"message": "Short names", "weight": 45}],
            }
        )
        warning.encode("ascii")
        self.assertNotIn("\U0001f600", warning)

    def test_doctor_json(self) -> None:
        code, output, _ = run_cli(["doctor", "--json"])
        payload = json.loads(output)
        self.assertTrue(payload["python"].startswith("3."))
        self.assertIn("decompiler", payload)
        self.assertIn(code, (0, 1))


if __name__ == "__main__":
    unittest.main()
