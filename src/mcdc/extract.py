"""Guarded extraction of archive entries."""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import ExtractionError
from .jarinfo import JarInfo, JarSource
from .util import is_symlink_entry, safe_target

SIGNATURE_RE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.IGNORECASE)

DEFAULT_MAX_EXTRACT_BYTES = 2048 * 1024 * 1024
MAX_ENTRIES = 250_000


@dataclass
class ExtractionStats:
    files: int = 0
    bytes: int = 0
    skipped: int = 0
    duplicates: int = 0


def _copy_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with zf.open(info, "r") as source, destination.open("wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            target.write(chunk)
    if written != info.file_size:
        try:
            destination.unlink()
        except OSError:
            pass
        raise ExtractionError(
            f"Short read while extracting {info.filename}: "
            f"expected {info.file_size} bytes, wrote {written}"
        )
    return written


def _validate_entries(infos: list, max_total_bytes: int) -> None:
    if len(infos) > MAX_ENTRIES:
        raise ExtractionError(
            f"Archive has too many entries ({len(infos):,}); refusing to extract it."
        )
    total = sum(info.file_size for info in infos if not info.is_dir())
    if total > max_total_bytes:
        raise ExtractionError(
            f"Archive expands to {total:,} bytes, above the configured limit of "
            f"{max_total_bytes:,} bytes. Use --max-extract-mb to raise it."
        )


def extract_classes(
    source: JarSource,
    info: JarInfo,
    destination: Path,
    max_total_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> ExtractionStats:
    """Extract only class entries, preserving their package paths."""
    stats = ExtractionStats()
    destination.mkdir(parents=True, exist_ok=True)

    with source.open() as zf:
        infos = zf.infolist()
        class_infos = [
            item for item in infos if not item.is_dir() and item.filename.lower().endswith(".class")
        ]
        _validate_entries(class_infos, max_total_bytes)

        seen = set()
        for item in class_infos:
            member = item.filename.replace("\\", "/")
            if is_symlink_entry(item):
                raise ExtractionError(f"Symlink archive entry is not allowed: {member}")
            target = safe_target(destination, member)
            if member in seen:
                stats.duplicates += 1
            seen.add(member)
            stats.bytes += _copy_entry(zf, item, target)
            stats.files += 1

    return stats


def extract_resources(
    source: JarSource,
    info: JarInfo,
    destination: Path,
    max_total_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> ExtractionStats:
    """Copy non-class resources without overwriting decompiled Java files."""
    stats = ExtractionStats()
    destination.mkdir(parents=True, exist_ok=True)

    with source.open() as zf:
        infos = [
            item
            for item in zf.infolist()
            if not item.is_dir()
            and not item.filename.lower().endswith(".class")
            and not SIGNATURE_RE.match(item.filename.replace("\\", "/"))
        ]
        _validate_entries(infos, max_total_bytes)

        seen = set()
        for item in infos:
            member = item.filename.replace("\\", "/")
            if is_symlink_entry(item):
                stats.skipped += 1
                continue
            target = safe_target(destination, member)
            if target.exists():
                stats.skipped += 1
                continue
            if member in seen:
                stats.duplicates += 1
            seen.add(member)
            stats.bytes += _copy_entry(zf, item, target)
            stats.files += 1

    return stats
