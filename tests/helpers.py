from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, Optional

JAVAC = shutil.which("javac")


def require_javac() -> str:
    if not JAVAC:
        raise RuntimeError("javac is required for this test")
    return JAVAC


def compile_sources(
    root: Path,
    sources: Dict[str, str],
    debug: bool = True,
) -> Path:
    """Compile a mapping of source paths to Java code and return the class dir."""
    source_root = root / "src"
    for relative, content in sources.items():
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    class_root = root / "classes"
    class_root.mkdir(parents=True, exist_ok=True)
    command = [require_javac(), "-d", str(class_root)]
    if not debug:
        command.append("-g:none")
    command.extend(str(path) for path in sorted(source_root.rglob("*.java")))
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"javac failed:\n{result.stdout}")
    return class_root


def build_jar(
    root: Path,
    sources: Dict[str, str],
    jar_name: str = "fixture.jar",
    debug: bool = True,
    manifest: Optional[str] = None,
    extra_entries: Optional[Dict[str, bytes]] = None,
) -> Path:
    class_root = compile_sources(root, sources, debug=debug)
    jar_path = root / jar_name
    with zipfile.ZipFile(jar_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if manifest is not None:
            zf.writestr("META-INF/MANIFEST.MF", manifest)
        for class_file in sorted(class_root.rglob("*.class")):
            zf.write(class_file, class_file.relative_to(class_root).as_posix())
        for name, data in (extra_entries or {}).items():
            zf.writestr(name, data)
    return jar_path


def build_zip(root: Path, name: str, entries: Dict[str, bytes]) -> Path:
    path = root / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry_name, data in entries.items():
            zf.writestr(entry_name, data)
    return path


CLEAN_SOURCES = {
    "com/example/Alpha.java": """
        package com.example;
        public class Alpha {
            private final int value;
            public Alpha(int value) { this.value = value; }
            public int doubled() { return value * 2; }
        }
    """,
    "com/example/Beta.java": """
        package com.example;
        public class Beta {
            public String label() { return "beta"; }
        }
    """,
    "com/example/Gamma.java": """
        package com.example;
        public final class Gamma {
            public static int add(int left, int right) { return left + right; }
        }
    """,
    "com/example/Delta.java": """
        package com.example;
        public interface Delta {
            void run();
        }
    """,
    "com/example/Epsilon.java": """
        package com.example;
        public enum Epsilon { ONE, TWO }
    """,
    "com/example/Zeta.java": """
        package com.example;
        public record Zeta(String name, int count) { }
    """,
}

OBFUSCATED_SOURCES = {
    "a.java": "public class a { public static int x(int y) { return y + 1; } }",
    "b.java": "public class b { public int c; public void d() { c = 1; } }",
    "c.java": "public class c { public String e() { return \"value\"; } }",
    "d.java": "public class d { public long f(long g) { return g * g; } }",
    "e.java": "public class e { public boolean h() { return true; } }",
    "f.java": "public class f { public void i() { System.out.println(\"x\"); } }",
}

THREE_CHAR_SOURCES = {
    "aaa.java": "public class aaa { public static int x(int y) { return y + 1; } }",
    "aab.java": "public class aab { public int c; public void d() { c = 1; } }",
    "aac.java": "public class aac { public String e() { return \"value\"; } }",
    "aad.java": "public class aad { public long f(long g) { return g * g; } }",
    "aae.java": "public class aae { public boolean h() { return true; } }",
    "aaf.java": "public class aaf { public void i() { System.out.println(\"x\"); } }",
}

MINECRAFT_SOURCES = {
    **OBFUSCATED_SOURCES,
    "net/minecraft/client/main/Main.java": """
        package net.minecraft.client.main;
        public class Main {
            public static void main(String[] args) {
                System.out.println("main");
            }
        }
    """,
}
