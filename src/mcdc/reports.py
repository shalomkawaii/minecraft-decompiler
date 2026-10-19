"""Rendering of analysis warnings and decompile reports."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, Iterable, List

BANNER_WIDTH = 78


def _wrap(text: str, width: int = BANNER_WIDTH) -> List[str]:
    return textwrap.wrap(
        " ".join(text.split()),
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def render_warning(analysis: Dict[str, Any]) -> str:
    """Return an ASCII warning block. No emojis, no ANSI color."""
    lines = ["=" * BANNER_WIDTH]
    title = analysis.get("warning_title")
    if not title:
        if analysis.get("detected") and analysis.get("likely_official_minecraft"):
            title = "OBFUSCATED MINECRAFT JAR DETECTED"
        elif analysis.get("detected"):
            title = "OBFUSCATION DETECTED"
        else:
            title = "POSSIBLE OBFUSCATION"
    lines.append(f" WARNING: {title}")
    lines.append(
        f" Confidence: {analysis.get('confidence', 0)}/100 "
        f"({analysis.get('level', 'unknown')})"
    )
    lines.append("=" * BANNER_WIDTH)
    lines.append("")
    for advice in analysis.get("advice", [])[:2]:
        lines.extend(_wrap(advice))
        lines.append("")
    reasons = analysis.get("reasons", [])
    if reasons:
        lines.append("Signals:")
        for reason in reasons[:6]:
            lines.append(f" - {reason.get('message', '')}")
        lines.append("")
    lines.append("=" * BANNER_WIDTH)
    return "\n".join(lines)


def format_analysis(analysis: Dict[str, Any], max_reasons: int = 8) -> str:
    state = "DETECTED" if analysis.get("detected") else "not detected"
    lines = [
        f"Obfuscation: {state} (confidence {analysis.get('confidence', 0)}/100, "
        f"{analysis.get('level', 'unknown')})"
    ]
    if analysis.get("likely_official_minecraft"):
        lines[0] += " [official Minecraft pattern]"
    elif analysis.get("official_minecraft"):
        lines[0] += " [official Minecraft jar, readable names]"
    for reason in analysis.get("reasons", [])[:max_reasons]:
        lines.append(f"  - {reason.get('message', '')} (+{reason.get('weight', 0)})")
    for note in analysis.get("notes", []):
        lines.append(f"  note: {note}")
    if not analysis.get("detected"):
        for advice in analysis.get("advice", [])[:1]:
            lines.append(f"  {advice}")
    return "\n".join(lines)


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(rows: Iterable[tuple], headers: tuple) -> List[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(" --- " for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md(cell) for cell in row) + " |")
    return lines


def render_markdown(report: Dict[str, Any]) -> str:
    input_info = report.get("input", {})
    analysis = report.get("obfuscation", {})
    output = report.get("output", {})
    decompiler = report.get("decompiler", {})

    lines: List[str] = []
    lines.append("# mcdc decompile report")
    lines.append("")
    lines.append(f"Generated: {report.get('generated_at', '')}")
    lines.append("")
    lines.append("## Input")
    lines.append("")
    input_rows = [
        ("File", input_info.get("path", "")),
        ("SHA-256", input_info.get("sha256", "")),
        ("Size", input_info.get("size_bytes", "")),
        ("Kind", input_info.get("kind_label", input_info.get("kind", ""))),
        ("Loader", input_info.get("loader") or "none"),
        ("Minecraft version", input_info.get("mc_version") or "unknown"),
        ("Main class", input_info.get("main_class") or "unknown"),
        ("Classes", input_info.get("class_count", 0)),
        ("Resources", input_info.get("resource_count", 0)),
        ("Uncompressed size", input_info.get("total_uncompressed_bytes", 0)),
    ]
    if input_info.get("bundled_jar"):
        input_rows.append(("Bundled server jar", input_info["bundled_jar"]))
    lines.extend(_table(input_rows, ("Field", "Value")))
    lines.append("")

    lines.append("## Obfuscation analysis")
    lines.append("")
    detected = "yes" if analysis.get("detected") else "no"
    lines.append(f"**Detected:** {detected}")
    lines.append("")
    lines.append(
        f"**Confidence:** {analysis.get('confidence', 0)}/100 "
        f"({analysis.get('level', 'unknown')})"
    )
    lines.append("")
    if analysis.get("detected"):
        lines.append("```")
        lines.append(render_warning(analysis))
        lines.append("```")
        lines.append("")
    for advice in analysis.get("advice", []):
        lines.append(f"- {advice}")
    lines.append("")

    reasons = analysis.get("reasons", [])
    if reasons:
        lines.append("### Signals")
        lines.append("")
        lines.extend(
            _table(
                (
                    (
                        reason.get("weight", 0),
                        reason.get("code", ""),
                        reason.get("message", ""),
                    )
                    for reason in reasons
                ),
                ("Weight", "Signal", "Detail"),
            )
        )
        lines.append("")

    metrics = analysis.get("metrics", {})
    metric_rows = [
        ("Class count", metrics.get("class_count", 0)),
        ("Parsed classes", metrics.get("parsed_class_count", 0)),
        ("Short class name ratio (<= 3 chars)", metrics.get("short_class_name_ratio", 0)),
        ("Very short class name ratio (<= 2 chars)", metrics.get("very_short_class_name_ratio", 0)),
        ("Default package ratio", metrics.get("default_package_ratio", 0)),
        ("Single-letter package ratio", metrics.get("single_letter_package_ratio", 0)),
        ("Missing SourceFile ratio", metrics.get("missing_source_file_ratio", 0)),
        ("Missing line-number ratio", metrics.get("missing_line_number_ratio", 0)),
        ("Synthetic class ratio", metrics.get("synthetic_class_ratio", 0)),
        ("Median class name length", metrics.get("median_class_name_length", 0)),
        ("Methods with bytecode", metrics.get("methods_with_code", 0)),
        ("Methods with line numbers", metrics.get("methods_with_line_numbers", 0)),
    ]
    lines.append("### Metrics")
    lines.append("")
    lines.extend(_table(metric_rows, ("Metric", "Value")))
    lines.append("")
    if analysis.get("markers"):
        lines.append("Obfuscator markers: " + ", ".join(analysis["markers"]))
        lines.append("")
    if analysis.get("hardening"):
        lines.append(
            "Hardening signals (informational, not proof of malicious behavior): "
            + ", ".join(analysis["hardening"])
        )
        lines.append("")
    if analysis.get("notes"):
        lines.append("### Notes")
        lines.append("")
        for note in analysis["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("## Output")
    lines.append("")
    output_rows = [
        ("Sources directory", output.get("sources_dir", "")),
        ("Java files", output.get("java_files", 0)),
        ("Class files", output.get("class_files", 0)),
        ("Missing classes", len(output.get("missing_classes", []))),
        ("Resource files copied", output.get("resource_files", 0)),
        ("Report JSON", output.get("report_json", "")),
        ("Report Markdown", output.get("report_md", "")),
        ("Decompiler log", output.get("decompiler_log", "")),
    ]
    lines.extend(_table(output_rows, ("Field", "Value")))
    lines.append("")

    lines.append("## Decompiler")
    lines.append("")
    lines.extend(
        _table(
            [
                ("Engine", decompiler.get("name", "Vineflower")),
                ("Version", decompiler.get("version", "")),
                ("Java", decompiler.get("java", "")),
                ("Threads", decompiler.get("threads", "")),
                ("Duration", f"{decompiler.get('duration_seconds', 0):.1f} s"),
            ],
            ("Field", "Value"),
        )
    )
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "Obfuscation detection is heuristic and is not a security audit. "
        "Decompile only jars you are allowed to inspect, and never run an untrusted jar."
    )
    lines.append("")
    return "\n".join(lines)
