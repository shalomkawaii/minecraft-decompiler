"""Inspect JAR files without executing anything from them."""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .errors import JarError
from .util import sha256_bytes, sha256_file

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_VERSION_JSON_BYTES = 1024 * 1024
MAX_NESTED_JAR_BYTES = 1024 * 1024 * 1024

_BUNDLED_SERVER_RE = re.compile(
    r"^META-INF/versions/[^/]+/server(?:-[^/]+)?\.jar$", re.IGNORECASE
)
_BUNDLED_LIBRARY_RE = re.compile(r"^META-INF/libraries/.+\.jar$", re.IGNORECASE)
_BUNDLED_VERSION_RE = re.compile(r"^META-INF/versions/([^/]+)/", re.IGNORECASE)
_SIGNATURE_RE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.IGNORECASE)

_KIND_LABELS = {
    "minecraft-client": "Minecraft client",
    "minecraft-server": "Minecraft server",
    "mod": "Minecraft mod",
    "library": "Java library",
}


@dataclass
class JarSource:
    """A jar on disk or a nested jar held in memory."""

    label: str
    path: Optional[Path] = None
    data: Optional[bytes] = None
    _sha256: Optional[str] = field(default=None, init=False, repr=False)

    def open(self) -> zipfile.ZipFile:
        if self.path is not None:
            return zipfile.ZipFile(self.path, "r")
        if self.data is not None:
            return zipfile.ZipFile(io.BytesIO(self.data), "r")
        raise JarError("Jar source has neither a path nor data")

    def sha256(self) -> str:
        if self._sha256 is None:
            if self.path is not None:
                self._sha256 = sha256_file(self.path)
            elif self.data is not None:
                self._sha256 = sha256_bytes(self.data)
            else:
                raise JarError("Jar source has neither a path nor data")
        return self._sha256

    def size_bytes(self) -> int:
        if self.path is not None:
            return self.path.stat().st_size
        return len(self.data or b"")

    def is_nested(self) -> bool:
        return self.data is not None


@dataclass
class JarInfo:
    source: JarSource
    entries: List[str]
    class_entries: List[str]
    resource_count: int
    total_uncompressed_bytes: int
    manifest: Dict[str, str]
    kind: str
    loader: Optional[str]
    mc_version: Optional[str]
    main_class: Optional[str]
    signed: bool
    duplicate_entries: List[str]
    nested_server_entry: Optional[str]
    nested_library_entries: List[str]
    is_multirelease: bool
    mod_metadata: List[str]

    @property
    def class_count(self) -> int:
        return len(self.class_entries)

    @property
    def kind_label(self) -> str:
        return _KIND_LABELS.get(self.kind, self.kind)


def parse_manifest(data: bytes) -> Dict[str, str]:
    text = data.decode("utf-8", "replace")
    result: Dict[str, str] = {}
    current: Optional[str] = None
    for line in re.split(r"\r\n|\r|\n", text):
        if not line:
            current = None
            continue
        if line.startswith(" ") and current is not None:
            result[current] += line[1:]
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current = key.strip()
            result[current] = value.strip()
    return result


def _read_small_entry(zf: zipfile.ZipFile, name: str, limit: int) -> Optional[bytes]:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > limit:
        return None
    try:
        return zf.read(info)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None


def _detect_loader(entry_set: set) -> Optional[str]:
    if "fabric.mod.json" in entry_set:
        return "Fabric"
    if "quilt.mod.json" in entry_set:
        return "Quilt"
    if "META-INF/neoforge.mods.toml" in entry_set:
        return "NeoForge"
    if "META-INF/mods.toml" in entry_set:
        return "Forge"
    if "mcmod.info" in entry_set:
        return "Forge (legacy)"
    return None


def _detect_kind(
    entry_set: set,
    manifest: Dict[str, str],
    loader: Optional[str],
) -> str:
    main_class = manifest.get("Main-Class", "")
    has_bundle_layout = bool(
        any(_BUNDLED_SERVER_RE.match(name) for name in entry_set)
        and any(_BUNDLED_LIBRARY_RE.match(name) for name in entry_set)
    )
    if main_class == "net.minecraft.bundler.Main" or has_bundle_layout:
        return "minecraft-server"
    if loader:
        return "mod"
    if (
        "net/minecraft/client/main/Main.class" in entry_set
        or main_class.startswith("net.minecraft.client")
    ):
        return "minecraft-client"
    if (
        "net/minecraft/server/MinecraftServer.class" in entry_set
        or main_class.startswith("net.minecraft.server")
    ):
        return "minecraft-server"
    return "library"


def _extract_version(
    entry_set: set,
    manifest: Dict[str, str],
    version_json: Optional[bytes],
) -> Optional[str]:
    for name in sorted(entry_set):
        match = _BUNDLED_VERSION_RE.match(name)
        if match and (name.lower().endswith(".jar")):
            return match.group(1)
    if version_json:
        try:
            payload = json.loads(version_json.decode("utf-8", "replace"))
            if isinstance(payload, dict) and payload.get("id"):
                return str(payload["id"])
        except (ValueError, UnicodeError):
            pass
    for key in ("Implementation-Version", "Specification-Version", "Minecraft-Version"):
        value = manifest.get(key)
        if value:
            return value
    return None


def inspect_jar(source: JarSource) -> JarInfo:
    """Read archive metadata and decide which kind of jar this is."""
    try:
        with source.open() as zf:
            infos = zf.infolist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise JarError(f"Not a readable JAR/ZIP file: {source.label}") from exc

    names: List[str] = []
    class_entries: List[str] = []
    resource_count = 0
    total_uncompressed = 0
    signed = False
    mod_metadata: List[str] = []
    encrypted = False

    for info in infos:
        name = info.filename.replace("\\", "/")
        if info.is_dir():
            continue
        if info.flag_bits & 0x1:
            encrypted = True
        names.append(name)
        total_uncompressed += info.file_size
        if name.lower().endswith(".class"):
            class_entries.append(name)
        else:
            resource_count += 1
        if _SIGNATURE_RE.match(name):
            signed = True
        if name in (
            "fabric.mod.json",
            "quilt.mod.json",
            "META-INF/mods.toml",
            "META-INF/neoforge.mods.toml",
            "mcmod.info",
        ):
            mod_metadata.append(name)

    if encrypted:
        raise JarError(
            f"Encrypted ZIP entries are not supported: {source.label}. "
            "Decrypt the archive before decompiling it."
        )

    entry_set = set(names)
    duplicate_entries = sorted(
        name for name, count in Counter(names).items() if count > 1
    )

    manifest: Dict[str, str] = {}
    version_json: Optional[bytes] = None
    try:
        with source.open() as zf:
            manifest_bytes = _read_small_entry(
                zf, "META-INF/MANIFEST.MF", MAX_MANIFEST_BYTES
            )
            if manifest_bytes:
                manifest = parse_manifest(manifest_bytes)
            version_json = _read_small_entry(
                zf, "version.json", MAX_VERSION_JSON_BYTES
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise JarError(f"Cannot read archive metadata: {source.label}") from exc

    loader = _detect_loader(entry_set)
    kind = _detect_kind(entry_set, manifest, loader)
    nested_server = next(
        (name for name in sorted(entry_set) if _BUNDLED_SERVER_RE.match(name)),
        None,
    )
    nested_libraries = sorted(
        name for name in entry_set if _BUNDLED_LIBRARY_RE.match(name)
    )

    return JarInfo(
        source=source,
        entries=names,
        class_entries=class_entries,
        resource_count=resource_count,
        total_uncompressed_bytes=total_uncompressed,
        manifest=manifest,
        kind=kind,
        loader=loader,
        mc_version=_extract_version(entry_set, manifest, version_json),
        main_class=manifest.get("Main-Class"),
        signed=signed,
        duplicate_entries=duplicate_entries,
        nested_server_entry=nested_server,
        nested_library_entries=nested_libraries,
        is_multirelease=any(
            name.startswith("META-INF/versions/") and name.endswith(".class")
            for name in names
        ),
        mod_metadata=mod_metadata,
    )


def read_nested_jar(
    source: JarSource,
    entry_name: str,
    max_bytes: int = MAX_NESTED_JAR_BYTES,
) -> JarSource:
    """Read a bundled jar from inside another jar, with a size guard."""
    try:
        with source.open() as zf:
            info = zf.getinfo(entry_name)
            if info.file_size > max_bytes:
                raise JarError(
                    f"Nested jar is too large to process safely "
                    f"({info.file_size} bytes): {entry_name}"
                )
            data = zf.read(info)
    except KeyError as exc:
        raise JarError(f"Bundled jar not found: {entry_name}") from exc
    except (OSError, zipfile.BadZipFile) as exc:
        raise JarError(f"Cannot read bundled jar: {entry_name}") from exc

    nested = JarSource(label=f"{source.label}!/{entry_name}", data=data)
    try:
        with nested.open():
            pass
    except zipfile.BadZipFile as exc:
        raise JarError(f"Bundled entry is not a valid jar: {entry_name}") from exc
    return nested


def is_valid_jar(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return zf.testzip() is None
    except (OSError, zipfile.BadZipFile):
        return False
