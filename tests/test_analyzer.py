from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from mcdc.analyzer import analyze_jar
from mcdc.errors import ExtractionError
from mcdc.extract import extract_classes
from mcdc.jarinfo import JarSource, inspect_jar, read_nested_jar
from mcdc.util import safe_target
from tests.helpers import (
    CLEAN_SOURCES,
    MINECRAFT_SOURCES,
    OBFUSCATED_SOURCES,
    THREE_CHAR_SOURCES,
    build_jar,
    build_zip,
)


class AnalyzerTests(unittest.TestCase):
    def test_clean_jar_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, CLEAN_SOURCES)
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            analysis = analyze_jar(info)
            self.assertFalse(analysis.detected, analysis.summary)
            self.assertLess(analysis.confidence, 45)
            self.assertEqual(analysis.markers, [])

    def test_obfuscated_jar_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, OBFUSCATED_SOURCES, debug=False)
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            analysis = analyze_jar(info)
            self.assertTrue(analysis.detected, analysis.summary)
            self.assertIn(analysis.level, ("medium", "high"))
            self.assertGreaterEqual(analysis.confidence, 45)
            self.assertTrue(any(reason.code == "short_class_names" for reason in analysis.reasons))
            self.assertTrue(any(reason.code == "missing_line_numbers" for reason in analysis.reasons))

    def test_three_character_names_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(root, THREE_CHAR_SOURCES, debug=False)
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            analysis = analyze_jar(info)
            self.assertTrue(analysis.detected, analysis.summary)
            self.assertGreaterEqual(analysis.metrics["short_class_name_ratio"], 0.99)

    def test_official_deobfuscated_jar_is_identified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = "Manifest-Version: 1.0\r\nMain-Class: net.minecraft.server.MinecraftServer\r\n\r\n"
            jar = build_jar(root, CLEAN_SOURCES, manifest=manifest)
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            self.assertEqual(info.kind, "minecraft-server")
            analysis = analyze_jar(info)
            self.assertFalse(analysis.detected)
            self.assertTrue(analysis.official_minecraft)
            self.assertIn("readable class names", " ".join(analysis.advice))

    def test_official_minecraft_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = "Manifest-Version: 1.0\r\nMain-Class: net.minecraft.client.main.Main\r\n\r\n"
            jar = build_jar(
                root,
                MINECRAFT_SOURCES,
                debug=False,
                manifest=manifest,
            )
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            self.assertEqual(info.kind, "minecraft-client")
            analysis = analyze_jar(info)
            self.assertTrue(analysis.detected)
            self.assertTrue(analysis.likely_official_minecraft)
            self.assertIn("official Minecraft", " ".join(analysis.advice))

    def test_bundler_jar_exposes_nested_server(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inner = build_jar(root, CLEAN_SOURCES, jar_name="server-1.21.4.jar")
            inner_bytes = inner.read_bytes()
            outer = build_zip(
                root,
                "server.jar",
                {
                    "META-INF/MANIFEST.MF": (
                        b"Manifest-Version: 1.0\r\nMain-Class: net.minecraft.bundler.Main\r\n\r\n"
                    ),
                    "META-INF/libraries/example.jar": inner_bytes,
                    "META-INF/versions/1.21.4/server-1.21.4.jar": inner_bytes,
                },
            )
            info = inspect_jar(JarSource(label=str(outer), path=outer))
            self.assertEqual(info.kind, "minecraft-server")
            self.assertEqual(
                info.nested_server_entry, "META-INF/versions/1.21.4/server-1.21.4.jar"
            )
            self.assertEqual(info.mc_version, "1.21.4")
            nested = read_nested_jar(info.source, info.nested_server_entry)
            nested_info = inspect_jar(nested)
            self.assertGreater(nested_info.class_count, 0)

    def test_zip_slip_names_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "out"
            root.mkdir()
            for name in ("../evil", "/absolute/evil", "C:/evil", "a/../../evil"):
                with self.assertRaises(ExtractionError):
                    safe_target(root, name)

    def test_extract_rejects_zip_slip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_zip(root, "evil.jar", {"../evil.class": b"bad"})
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            with self.assertRaises(ExtractionError):
                extract_classes(info.source, info, root / "classes")

    def test_extracts_classes_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = build_jar(
                root,
                CLEAN_SOURCES,
                extra_entries={"assets/example.txt": b"hello"},
            )
            info = inspect_jar(JarSource(label=str(jar), path=jar))
            stats = extract_classes(info.source, info, root / "classes")
            self.assertEqual(stats.files, 6)
            self.assertTrue((root / "classes" / "com" / "example" / "Alpha.class").exists())
            self.assertFalse((root / "classes" / "assets" / "example.txt").exists())


if __name__ == "__main__":
    unittest.main()
