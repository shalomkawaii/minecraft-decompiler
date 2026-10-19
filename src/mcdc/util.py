"""Small shared helpers with no third-party dependencies."""

from __future__ import annotations

import hashlib
import os
import re
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Optional

from .errors import ExtractionError


def human_bytes(value: int) -> str:
    """Format a byte count using binary units."""
    number = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(number) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(number)} B"
            return f"{number:.1f} {unit}"
        number /= 1024.0
    return f"{int(value)} B"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, rest = divmod(int(round(seconds)), 60)
    return f"{minutes} min {rest} s"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def sanitize_stem(name: str) -> str:
    """Turn a file name into a safe directory name."""
    stem = name
    if stem.lower().endswith(".jar"):
        stem = stem[:-4]
    stem = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", stem)
    stem = stem.strip(" .")
    stem = re.sub(r"\s+", " ", stem)
    if len(stem) > 80:
        stem = stem[:80].rstrip(" .")
    if not stem:
        stem = "jar"
    if stem.lower() in _WINDOWS_RESERVED:
        stem = f"_{stem}"
    return stem


def safe_target(root: Path, member: str) -> Path:
    """Resolve an archive member inside root, rejecting traversal and absolute paths."""
    if not member or "\x00" in member:
        raise ExtractionError(f"Unsafe archive entry name: {member!r}")

    normalized = member.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ExtractionError(f"Absolute archive entry is not allowed: {member}")

    parts = []
    for part in PurePosixPath(normalized).parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ExtractionError(f"Path traversal is not allowed: {member}")
        parts.append(part)

    if not parts:
        raise ExtractionError(f"Empty archive entry name: {member!r}")

    target = root.joinpath(*parts)
    root_resolved = Path(os.path.normcase(str(root.resolve())))
    target_resolved = Path(os.path.normcase(str(target.resolve())))
    try:
        common = Path(os.path.commonpath([str(root_resolved), str(target_resolved)]))
    except ValueError as exc:
        raise ExtractionError(f"Unsafe archive entry name: {member}") from exc
    if common != root_resolved:
        raise ExtractionError(f"Archive entry escapes the output directory: {member}")
    return target


def is_symlink_entry(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def parse_java_major(version_output: str) -> Optional[int]:
    """Extract the feature version from `java -version` output."""
    match = re.search(r'version\s+"([^"]+)"', version_output)
    if not match:
        match = re.search(r"openjdk\s+([0-9][^\s]*)", version_output)
    if not match:
        return None
    raw = match.group(1)
    if raw.startswith("1."):
        raw = raw[2:]
    digits = re.match(r"(\d+)", raw)
    if not digits:
        return None
    return int(digits.group(1))


def parse_java_version_line(version_output: str) -> str:
    match = re.search(r'version\s+"([^"]+)"', version_output)
    if match:
        return match.group(1)
    first = version_output.strip().splitlines()
    return first[0].strip() if first else "unknown"


class Console:
    """Minimal console writer; keeps JSON stdout clean."""

    def __init__(self, quiet: bool = False, stream=None) -> None:
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self._started = time.time()

    def line(self, message: str = "") -> None:
        if not self.quiet:
            print(message, file=self.stream, flush=True)

    def step(self, index: int, total: int, message: str) -> None:
        if not self.quiet:
            print(f"[{index}/{total}] {message}", file=self.stream, flush=True)

    def warning(self, message: str) -> None:
        if not self.quiet:
            print(message, file=self.stream, flush=True)

    def error(self, message: str) -> None:
        print(f"error: {message}", file=sys.stderr, flush=True)

    def note(self, message: str) -> None:
        if not self.quiet:
            print(f"note: {message}", file=self.stream, flush=True)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
