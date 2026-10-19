"""Heuristic obfuscation detection for Java archives.

The analyzer is deliberately conservative: it explains every signal and never
claims that a jar is malicious. Obfuscation and malware are different things.
"""

from __future__ import annotations

import statistics
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .classfile import ClassFormatError, ClassInfo, fallback_class_info, parse_class, split_class_path
from .jarinfo import JarInfo
from .util import human_bytes

MAX_CLASS_BYTES = 64 * 1024 * 1024


@dataclass
class Reason:
    code: str
    message: str
    weight: int
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Analysis:
    detected: bool
    level: str
    confidence: int
    likely_official_minecraft: bool
    official_minecraft: bool
    summary: str
    reasons: List[Reason]
    metrics: Dict[str, Any]
    markers: List[str]
    hardening: List[str]
    advice: List[str]
    notes: List[str]

    @property
    def warning_title(self) -> str:
        if self.detected and self.likely_official_minecraft:
            return "OBFUSCATED MINECRAFT JAR DETECTED"
        if self.detected:
            return "OBFUSCATION DETECTED"
        if self.level == "low":
            return "POSSIBLE OBFUSCATION"
        return "NO STRONG OBFUSCATION DETECTED"


def _ratio(numerator: int, denominator: int) -> float:
    return (numerator / denominator) if denominator else 0.0


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def analyze_jar(info: JarInfo) -> Analysis:
    """Analyze every class entry and return a transparent score."""
    class_names: List[str] = []
    parsed: List[ClassInfo] = []
    parse_errors: List[str] = []
    marker_counts: Counter = Counter()
    hardening_counts: Counter = Counter()
    major_versions: Counter = Counter()
    name_lengths: List[int] = []

    try:
        with info.source.open() as zf:
            for name in info.class_entries:
                _, _, base = split_class_path(name)
                class_names.append(name)
                if base not in ("module-info", "package-info"):
                    name_lengths.append(len(base))
                try:
                    entry = zf.getinfo(name)
                    if entry.file_size > MAX_CLASS_BYTES:
                        raise ValueError(
                            f"class entry is larger than {MAX_CLASS_BYTES} bytes"
                        )
                    data = zf.read(entry)
                except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                    parse_errors.append(name)
                    parsed.append(fallback_class_info(name, str(exc)))
                    continue
                try:
                    class_info = parse_class(name, data)
                except (ClassFormatError, ValueError, IndexError) as exc:
                    parse_errors.append(name)
                    parsed.append(fallback_class_info(name, str(exc)))
                    continue
                parsed.append(class_info)
                major_versions[class_info.major_version] += 1
                for hit in class_info.marker_hits:
                    marker_counts[hit] += 1
                for hit in class_info.hardening_hits:
                    hardening_counts[hit] += 1
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Could not read class entries: {exc}") from exc

    total_classes = len(class_names)
    parsed_classes = [item for item in parsed if item.parse_error is None]
    parsed_count = len(parsed_classes)

    short_names = 0
    very_short_names = 0
    inner_names = 0
    synthetic = 0
    default_package = 0
    single_letter_package = 0
    missing_source_file = 0
    methods_with_code = 0
    methods_with_lines = 0

    for class_info in parsed:
        if class_info.is_short_name:
            short_names += 1
        if class_info.is_very_short_name:
            very_short_names += 1
        if "$" in class_info.simple_name:
            inner_names += 1
        if class_info.is_synthetic:
            synthetic += 1
        if not class_info.package:
            default_package += 1
        elif any(len(part) == 1 for part in class_info.package.split("/")):
            single_letter_package += 1
        if class_info.parse_error is None:
            if not class_info.has_source_file:
                missing_source_file += 1
            methods_with_code += class_info.methods_with_code
            methods_with_lines += class_info.methods_with_lines

    short_ratio = _ratio(short_names, total_classes)
    very_short_ratio = _ratio(very_short_names, total_classes)
    inner_ratio = _ratio(inner_names, total_classes)
    synthetic_ratio = _ratio(synthetic, total_classes)
    default_ratio = _ratio(default_package, total_classes)
    single_letter_ratio = _ratio(single_letter_package, total_classes)
    source_missing_ratio = _ratio(missing_source_file, parsed_count)
    line_missing_ratio = _ratio(methods_with_code - methods_with_lines, methods_with_code)
    median_name_length = statistics.median(name_lengths) if name_lengths else 0

    proguard_configs = sorted(
        name
        for name in info.entries
        if name.startswith("META-INF/proguard/") or name.lower().endswith(".pro")
    )
    markers = sorted(marker_counts)
    hardening = sorted(hardening_counts)

    score = 0
    reasons: List[Reason] = []
    notes: List[str] = []

    def add(points: int, code: str, message: str, **details: Any) -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        reasons.append(Reason(code=code, message=message, weight=points, details=details))

    if total_classes == 0:
        return Analysis(
            detected=False,
            level="none",
            confidence=0,
            likely_official_minecraft=False,
            official_minecraft=info.kind in ("minecraft-client", "minecraft-server"),
            summary="No class files found in this archive.",
            reasons=[],
            metrics={
                "class_count": 0,
                "resource_count": info.resource_count,
                "total_uncompressed_bytes": info.total_uncompressed_bytes,
            },
            markers=[],
            hardening=[],
            advice=["This archive does not contain Java classes, so there is nothing to decompile."],
            notes=[],
        )

    if short_ratio >= 0.75:
        add(
            45,
            "short_class_names",
            f"{_pct(short_ratio)} of classes have names with three characters or fewer.",
            ratio=round(short_ratio, 4),
            count=short_names,
        )
    elif short_ratio >= 0.50:
        add(
            38,
            "short_class_names",
            f"{_pct(short_ratio)} of classes have names with three characters or fewer.",
            ratio=round(short_ratio, 4),
            count=short_names,
        )
    elif short_ratio >= 0.30:
        add(
            28,
            "short_class_names",
            f"{_pct(short_ratio)} of classes have names with three characters or fewer.",
            ratio=round(short_ratio, 4),
            count=short_names,
        )
    elif short_ratio >= 0.15:
        add(
            14,
            "short_class_names",
            f"{_pct(short_ratio)} of classes have very short names.",
            ratio=round(short_ratio, 4),
            count=short_names,
        )

    if default_ratio >= 0.50:
        add(
            8,
            "default_package",
            f"{_pct(default_ratio)} of classes are in the default package.",
            ratio=round(default_ratio, 4),
            count=default_package,
        )
    elif default_ratio >= 0.25:
        add(
            4,
            "default_package",
            f"{_pct(default_ratio)} of classes are in the default package.",
            ratio=round(default_ratio, 4),
            count=default_package,
        )

    if single_letter_ratio >= 0.50:
        add(
            10,
            "single_letter_packages",
            f"{_pct(single_letter_ratio)} of classes are in packages with single-letter segments.",
            ratio=round(single_letter_ratio, 4),
            count=single_letter_package,
        )
    elif single_letter_ratio >= 0.20:
        add(
            5,
            "single_letter_packages",
            f"{_pct(single_letter_ratio)} of classes are in packages with single-letter segments.",
            ratio=round(single_letter_ratio, 4),
            count=single_letter_package,
        )

    if source_missing_ratio >= 0.90:
        add(
            15,
            "missing_source_file",
            f"{_pct(source_missing_ratio)} of classes have no SourceFile debug attribute.",
            ratio=round(source_missing_ratio, 4),
            count=missing_source_file,
        )
    elif source_missing_ratio >= 0.60:
        add(
            8,
            "missing_source_file",
            f"{_pct(source_missing_ratio)} of classes have no SourceFile debug attribute.",
            ratio=round(source_missing_ratio, 4),
            count=missing_source_file,
        )
    elif source_missing_ratio >= 0.30:
        add(
            3,
            "missing_source_file",
            f"{_pct(source_missing_ratio)} of classes have no SourceFile debug attribute.",
            ratio=round(source_missing_ratio, 4),
            count=missing_source_file,
        )

    if line_missing_ratio >= 0.90:
        add(
            12,
            "missing_line_numbers",
            f"{_pct(line_missing_ratio)} of methods with bytecode have no line number table.",
            ratio=round(line_missing_ratio, 4),
            methods_with_code=methods_with_code,
        )
    elif line_missing_ratio >= 0.60:
        add(
            6,
            "missing_line_numbers",
            f"{_pct(line_missing_ratio)} of methods with bytecode have no line number table.",
            ratio=round(line_missing_ratio, 4),
            methods_with_code=methods_with_code,
        )
    elif line_missing_ratio >= 0.30:
        add(
            2,
            "missing_line_numbers",
            f"{_pct(line_missing_ratio)} of methods with bytecode have no line number table.",
            ratio=round(line_missing_ratio, 4),
            methods_with_code=methods_with_code,
        )

    if synthetic_ratio >= 0.25:
        add(
            4,
            "synthetic_classes",
            f"{_pct(synthetic_ratio)} of classes are marked synthetic.",
            ratio=round(synthetic_ratio, 4),
            count=synthetic,
        )
    elif synthetic_ratio >= 0.10:
        add(
            2,
            "synthetic_classes",
            f"{_pct(synthetic_ratio)} of classes are marked synthetic.",
            ratio=round(synthetic_ratio, 4),
            count=synthetic,
        )

    if marker_counts:
        marker_points = min(40, 25 * len(marker_counts))
        add(
            marker_points,
            "obfuscator_markers",
            "Known obfuscator marker strings were found in the constant pool.",
            markers={name: count for name, count in sorted(marker_counts.items())},
        )

    if proguard_configs:
        add(
            15,
            "proguard_config",
            "The archive contains ProGuard configuration files.",
            files=proguard_configs[:20],
            count=len(proguard_configs),
        )

    if total_classes < 5:
        notes.append(
            f"Only {total_classes} class(es) were analyzed; confidence is reduced for tiny samples."
        )
        score = int(round(score * 0.85))

    confidence = max(0, min(100, int(round(score))))
    if confidence >= 70:
        level = "high"
    elif confidence >= 45:
        level = "medium"
    elif confidence >= 20:
        level = "low"
    else:
        level = "none"
    detected = level in ("high", "medium")
    official_minecraft = info.kind in ("minecraft-client", "minecraft-server")
    likely_official = detected and official_minecraft

    summary_bits = [
        f"{_pct(short_ratio)} short class names",
        f"{_pct(source_missing_ratio)} classes without SourceFile",
        f"{_pct(line_missing_ratio)} methods without line numbers",
    ]
    if marker_counts:
        summary_bits.append("markers: " + ", ".join(sorted(marker_counts)))
    summary = "; ".join(summary_bits) + "."

    advice: List[str] = []
    if likely_official:
        advice.append(
            "This looks like an official Minecraft jar. Decompiled names will be Mojang's "
            "obfuscated names (a, b, c, ...). Use official mappings if you need readable names."
        )
        advice.append(
            "Do not redistribute decompiled Minecraft game code. Decompile only jars you are "
            "allowed to inspect."
        )
    elif official_minecraft and not detected:
        advice.append(
            "This looks like an official Minecraft jar with readable class names and debug "
            "information. No obfuscation was detected, so decompiled names should be close to "
            "Mojang's source-level names."
        )
        advice.append(
            "Do not redistribute decompiled Minecraft game code. Decompile only jars you are "
            "allowed to inspect."
        )
    elif detected and info.kind == "mod":
        advice.append(
            "This third-party mod appears to be obfuscated. Review the original jar before running "
            "it and treat the decompiled output as untrusted."
        )
        advice.append(
            "String encryption or control-flow obfuscation may make the decompiled source "
            "incomplete or hard to read."
        )
    elif detected:
        advice.append(
            "The archive appears to be obfuscated. Public API names may remain intact, but internal "
            "names and debug information may be missing."
        )
    elif source_missing_ratio >= 0.60 or line_missing_ratio >= 0.60:
        advice.append(
            "No strong obfuscation was detected, but debug information is missing. Variable names "
            "and line numbers may be poor."
        )

    advice.append(
        "Obfuscation detection is heuristic and is not a security audit. Never run an untrusted jar."
    )

    if info.signed:
        notes.append(
            "The jar is signed. Signature files are not part of the source output."
        )
    if info.duplicate_entries:
        notes.append(
            f"The archive contains {len(info.duplicate_entries)} duplicate entr"
            f"{'y' if len(info.duplicate_entries) == 1 else 'ies'}."
        )
    if info.is_multirelease:
        notes.append(
            "This is a multi-release jar; classes under META-INF/versions may duplicate base classes."
        )
    if info.loader:
        notes.append(f"Mod loader metadata detected: {info.loader}.")
    if hardening:
        notes.append(
            "Hardening signals (informational, not proof of malicious behavior): "
            + ", ".join(hardening)
            + "."
        )
    if parse_errors:
        notes.append(
            f"{len(parse_errors)} class file(s) could not be parsed and were analyzed by name only."
        )

    metrics = {
        "class_count": total_classes,
        "parsed_class_count": parsed_count,
        "parse_failure_count": len(parse_errors),
        "resource_count": info.resource_count,
        "total_uncompressed_bytes": info.total_uncompressed_bytes,
        "short_class_name_ratio": round(short_ratio, 4),
        "very_short_class_name_ratio": round(very_short_ratio, 4),
        "inner_class_ratio": round(inner_ratio, 4),
        "default_package_ratio": round(default_ratio, 4),
        "single_letter_package_ratio": round(single_letter_ratio, 4),
        "missing_source_file_ratio": round(source_missing_ratio, 4),
        "missing_line_number_ratio": round(line_missing_ratio, 4),
        "synthetic_class_ratio": round(synthetic_ratio, 4),
        "median_class_name_length": median_name_length,
        "methods_with_code": methods_with_code,
        "methods_with_line_numbers": methods_with_lines,
        "class_file_major_versions": dict(sorted(major_versions.items())),
        "obfuscator_marker_counts": dict(sorted(marker_counts.items())),
        "hardening_signal_counts": dict(sorted(hardening_counts.items())),
        "proguard_config_count": len(proguard_configs),
        "parse_error_examples": parse_errors[:10],
    }

    return Analysis(
        detected=detected,
        level=level,
        confidence=confidence,
        likely_official_minecraft=likely_official,
        official_minecraft=official_minecraft,
        summary=summary,
        reasons=sorted(reasons, key=lambda reason: (-reason.weight, reason.code)),
        metrics=metrics,
        markers=markers,
        hardening=hardening,
        advice=advice,
        notes=notes,
    )


def analysis_to_dict(analysis: Analysis) -> Dict[str, Any]:
    return {
        "detected": analysis.detected,
        "level": analysis.level,
        "confidence": analysis.confidence,
        "likely_official_minecraft": analysis.likely_official_minecraft,
        "official_minecraft": analysis.official_minecraft,
        "summary": analysis.summary,
        "reasons": [
            {
                "code": reason.code,
                "message": reason.message,
                "weight": reason.weight,
                "details": reason.details,
            }
            for reason in analysis.reasons
        ],
        "metrics": analysis.metrics,
        "markers": analysis.markers,
        "hardening": analysis.hardening,
        "advice": analysis.advice,
        "notes": analysis.notes,
    }


def describe_jar(info: JarInfo) -> List[str]:
    """Short human-readable facts used by CLI summaries."""
    lines = [
        f"Kind: {info.kind_label}"
        + (f" ({info.loader})" if info.loader else ""),
        f"Classes: {info.class_count:,}",
        f"Resources: {info.resource_count:,}",
        f"Uncompressed size: {human_bytes(info.total_uncompressed_bytes)}",
    ]
    if info.mc_version:
        lines.append(f"Minecraft version: {info.mc_version}")
    if info.main_class:
        lines.append(f"Main class: {info.main_class}")
    return lines
