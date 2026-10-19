from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from mcdc.classfile import parse_class
from mcdc.errors import ClassFormatError
from tests.helpers import CLEAN_SOURCES, build_jar


class ClassFileTests(unittest.TestCase):
    def test_parses_debug_information(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, CLEAN_SOURCES, debug=True)
            with zipfile.ZipFile(jar) as zf:
                data = zf.read("com/example/Alpha.class")
            info = parse_class("com/example/Alpha.class", data)
            self.assertEqual(info.package, "com/example")
            self.assertEqual(info.simple_name, "Alpha")
            self.assertTrue(info.has_source_file)
            self.assertGreater(info.method_count, 0)
            self.assertGreater(info.methods_with_lines, 0)
            self.assertIsNone(info.parse_error)

    def test_detects_stripped_debug_information(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, CLEAN_SOURCES, debug=False)
            with zipfile.ZipFile(jar) as zf:
                data = zf.read("com/example/Alpha.class")
            info = parse_class("com/example/Alpha.class", data)
            self.assertFalse(info.has_source_file)
            self.assertEqual(info.methods_with_lines, 0)
            self.assertGreater(info.methods_with_code, 0)

    def test_rejects_non_class_data(self) -> None:
        with self.assertRaises(ClassFormatError):
            parse_class("Bad.class", b"not a class file")


if __name__ == "__main__":
    unittest.main()
