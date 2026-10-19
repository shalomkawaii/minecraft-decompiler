"""A defensive, dependency-free parser for the parts of a class file we need.

We do not verify bytecode. We only read the constant pool, method metadata and
debug attributes used by the obfuscation analyzer.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from .errors import ClassFormatError

# Strings that are associated with known obfuscators or hardening tools. These
# are hints, not proof: they only count when other signals agree.
OBFUSCATOR_MARKERS = {
    "Allatori": ("allatori",),
    "Zelix KlassMaster": ("zelix", "zkm"),
    "DashO": ("dasho", "preemptive"),
    "StringFog": ("stringfog",),
    "Skidfuscator": ("skidfuscator",),
    "Radon": ("radon",),
    "Paramorphism": ("paramorphism",),
    "Bozar": ("bozar",),
    "Branchlock": ("branchlock",),
}

HARDENING_MARKERS = {
    "Instrumentation API": ("java/lang/instrument",),
    "Dynamic class loading": ("defineclass", "urlclassloader"),
    "Reflection": ("java/lang/reflect/method", "setaccessible", "getdeclared"),
    "Cryptography": ("javax/crypto/cipher", "aes/gcm", "chacha20"),
    "Native libraries": ("system/loadlibrary", "loadlibrary0"),
    "Unsafe memory access": ("sun/misc/unsafe", "jdk/internal/misc/unsafe"),
    "Process execution": ("java/lang/processbuilder", "java/lang/runtime"),
}


@dataclass
class ClassInfo:
    """Metadata extracted from one class entry."""

    path: str
    package: str
    simple_name: str
    base_name: str
    major_version: int = 0
    access_flags: int = 0
    has_source_file: bool = False
    method_count: int = 0
    methods_with_code: int = 0
    methods_with_lines: int = 0
    field_count: int = 0
    inner_class_count: int = 0
    marker_hits: Set[str] = field(default_factory=set)
    hardening_hits: Set[str] = field(default_factory=set)
    parse_error: Optional[str] = None

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access_flags & 0x1000)

    @property
    def is_short_name(self) -> bool:
        return len(self.base_name) <= 3

    @property
    def is_very_short_name(self) -> bool:
        return len(self.base_name) <= 2


def split_class_path(path: str) -> tuple:
    normalized = path.replace("\\", "/")
    if normalized.lower().endswith(".class"):
        normalized = normalized[:-6]
    parts = [part for part in normalized.split("/") if part]
    simple = parts[-1] if parts else normalized
    package = "/".join(parts[:-1])
    base = simple.split("$", 1)[0]
    return package, simple, base


def fallback_class_info(path: str, error: str) -> ClassInfo:
    package, simple, base = split_class_path(path)
    return ClassInfo(
        path=path,
        package=package,
        simple_name=simple,
        base_name=base,
        parse_error=error,
    )


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _need(self, count: int) -> None:
        if count < 0 or self.pos + count > len(self.data):
            raise ClassFormatError("Unexpected end of class file")

    def u1(self) -> int:
        self._need(1)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u2(self) -> int:
        self._need(2)
        value = struct.unpack_from(">H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def u4(self) -> int:
        self._need(4)
        value = struct.unpack_from(">I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def take(self, count: int) -> bytes:
        self._need(count)
        value = self.data[self.pos : self.pos + count]
        self.pos += count
        return value

    def skip(self, count: int) -> None:
        self._need(count)
        self.pos += count


def _read_constant_pool(reader: _Reader) -> Dict[int, str]:
    count = reader.u2()
    if count == 0:
        raise ClassFormatError("Invalid constant pool size")
    utf8: Dict[int, str] = {}
    index = 1
    while index < count:
        tag = reader.u1()
        if tag == 1:  # Utf8
            length = reader.u2()
            raw = reader.take(length)
            try:
                value = raw.decode("utf-8", "replace")
            except Exception:
                value = raw.decode("latin-1", "replace")
            utf8[index] = value
        elif tag in (3, 4):  # Integer, Float
            reader.skip(4)
        elif tag in (5, 6):  # Long, Double (two slots)
            reader.skip(8)
            index += 1
        elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
            reader.skip(2)
        elif tag in (9, 10, 11, 12, 17, 18):  # refs, NameAndType, Dynamic
            reader.skip(4)
        elif tag == 15:  # MethodHandle
            reader.skip(3)
        else:
            raise ClassFormatError(f"Unknown constant pool tag {tag}")
        index += 1
    return utf8


def _scan_strings(utf8: Dict[int, str], info: ClassInfo) -> None:
    for value in utf8.values():
        if not value or len(value) > 512:
            continue
        lowered = value.lower()
        for label, needles in OBFUSCATOR_MARKERS.items():
            if label in info.marker_hits:
                continue
            if any(needle in lowered for needle in needles):
                info.marker_hits.add(label)
        for label, needles in HARDENING_MARKERS.items():
            if label in info.hardening_hits:
                continue
            if any(needle in lowered for needle in needles):
                info.hardening_hits.add(label)


def _attribute_end(reader: _Reader, length: int) -> int:
    end = reader.pos + length
    if end > len(reader.data):
        raise ClassFormatError("Attribute extends past end of class file")
    return end


def _parse_code_attribute(reader: _Reader, end: int, utf8: Dict[int, str]) -> bool:
    reader.u2()  # max_stack
    reader.u2()  # max_locals
    code_length = reader.u4()
    reader.skip(code_length)
    exception_count = reader.u2()
    reader.skip(exception_count * 8)
    attribute_count = reader.u2()
    has_lines = False
    for _ in range(attribute_count):
        name_index = reader.u2()
        length = reader.u4()
        attr_end = _attribute_end(reader, length)
        name = utf8.get(name_index, "")
        if name == "LineNumberTable":
            count = reader.u2()
            if count > 0:
                has_lines = True
        reader.pos = attr_end
    if reader.pos != end:
        reader.pos = end
    return has_lines


def _skip_member(
    reader: _Reader,
    utf8: Dict[int, str],
    methods: bool,
    info: ClassInfo,
) -> None:
    reader.u2()  # access flags
    reader.u2()  # name
    reader.u2()  # descriptor
    attribute_count = reader.u2()
    for _ in range(attribute_count):
        name_index = reader.u2()
        length = reader.u4()
        end = _attribute_end(reader, length)
        name = utf8.get(name_index, "")
        if methods and name == "Code":
            info.methods_with_code += 1
            if _parse_code_attribute(reader, end, utf8):
                info.methods_with_lines += 1
            reader.pos = end
        else:
            reader.pos = end
    if methods:
        info.method_count += 1
    else:
        info.field_count += 1


def parse_class(path: str, data: bytes) -> ClassInfo:
    """Parse a class entry. Raises ClassFormatError on malformed input."""
    if len(data) < 10:
        raise ClassFormatError("Class file is too small")

    reader = _Reader(data)
    magic = reader.u4()
    if magic != 0xCAFEBABE:
        raise ClassFormatError("Missing class file magic (0xCAFEBABE)")

    reader.u2()  # minor
    major = reader.u2()
    utf8 = _read_constant_pool(reader)

    access_flags = reader.u2()
    reader.u2()  # this_class
    reader.u2()  # super_class
    interface_count = reader.u2()
    reader.skip(interface_count * 2)

    field_count = reader.u2()
    info = ClassInfo(
        path=path,
        package="",
        simple_name="",
        base_name="",
        major_version=major,
        access_flags=access_flags,
    )
    for _ in range(field_count):
        _skip_member(reader, utf8, False, info)

    method_count = reader.u2()
    for _ in range(method_count):
        _skip_member(reader, utf8, True, info)

    class_attribute_count = reader.u2()
    for _ in range(class_attribute_count):
        name_index = reader.u2()
        length = reader.u4()
        end = _attribute_end(reader, length)
        name = utf8.get(name_index, "")
        if name == "SourceFile":
            info.has_source_file = True
        elif name == "InnerClasses":
            info.inner_class_count = reader.u2()
        reader.pos = end

    package, simple, base = split_class_path(path)
    info.package = package
    info.simple_name = simple
    info.base_name = base
    _scan_strings(utf8, info)
    return info
