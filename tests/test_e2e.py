from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from mcdc.cli import EXIT_OK, EXIT_STRICT, main
from tests.helpers import CLEAN_SOURCES, OBFUSCATED_SOURCES, build_jar


@unittest.skipUnless(
    os.environ.get("MCDC_RUN_E2E") == "1",
    "set MCDC_RUN_E2E=1 to run the Vineflower integration test",
)
class EndToEndTests(unittest.TestCase):
    def test_decompile_clean_jar(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, CLEAN_SOURCES)
            output = root / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                code = main(
                    [
                        "decompile",
                        str(jar),
                        "-o",
                        str(output),
                        "--quiet",
                        "--json",
                    ]
                )
            self.assertEqual(code, EXIT_OK, stdout.getvalue())
            payload = json.loads(stdout.getvalue())
            sources = Path(payload["output"]["sources_dir"])
            self.assertTrue((sources / "com" / "example" / "Alpha.java").exists())
            self.assertTrue((output / "fixture" / "report.json").exists())
            self.assertFalse(payload["obfuscation"]["detected"])

    def test_decompile_obfuscated_jar_with_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, OBFUSCATED_SOURCES, debug=False)
            output = root / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                code = main(
                    [
                        "decompile",
                        str(jar),
                        "-o",
                        str(output),
                        "--quiet",
                        "--json",
                        "--strict",
                    ]
                )
            self.assertEqual(code, EXIT_STRICT, stdout.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["obfuscation"]["detected"])
            sources = Path(payload["output"]["sources_dir"])
            self.assertTrue((sources / "a.java").exists())


if __name__ == "__main__":
    unittest.main()
