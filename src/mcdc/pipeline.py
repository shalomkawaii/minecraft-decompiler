"""End-to-end decompile pipeline."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .analyzer import Analysis, analyze_jar, analysis_to_dict
from .decompiler import (
    DecompilerInfo,
    JavaInfo,
    ensure_decompiler,
    find_java,
    run_decompiler,
)
from .errors import DecompilerError, JarError, McdcError, OutputError
from .extract import DEFAULT_MAX_EXTRACT_BYTES, extract_classes, extract_resources
from .jarinfo import JarInfo, JarSource, inspect_jar, read_nested_jar
from .reports import render_markdown, render_warning
from .util import Console, human_bytes, human_duration, sanitize_stem

OUTPUT_MARKER = ".mcdc-output"


@dataclass
class PipelineOptions:
    output_root: Path
    overwrite: bool = False
    with_resources: bool = False
    decompiler_path: Optional[str] = None
    java_path: Optional[str] = None
    allow_download: bool = True
    timeout: int = 900
    threads: int = 0
    quiet: bool = False
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES


def _bundle_input(
    source: JarSource,
    info: JarInfo,
) -> tuple:
    """Return the jar that actually contains the game classes."""
    if info.kind != "minecraft-server" or not info.nested_server_entry:
        return source, info, None
    nested = read_nested_jar(source, info.nested_server_entry)
    nested_info = inspect_jar(nested)
    return nested, nested_info, info.nested_server_entry


def _prepare_output_dir(path: Path, overwrite: bool) -> None:
    marker = path / OUTPUT_MARKER
    if path.exists():
        if not overwrite:
            raise OutputError(
                f"Output directory already exists: {path}. "
                "Use --overwrite to replace the previous mcdc output."
            )
        if not marker.exists():
            raise OutputError(
                f"Refusing to overwrite {path}: it was not created by mcdc. "
                "Choose another --output directory."
            )
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise OutputError(f"Cannot replace output directory {path}: {exc}") from exc
    try:
        path.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            f"Created by mcdc {__version__} at {datetime.now(timezone.utc).isoformat()}\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise OutputError(f"Cannot create output directory {path}: {exc}") from exc


def _count_java(sources: Path) -> int:
    return sum(1 for _ in sources.rglob("*.java"))


def _missing_classes(target: JarInfo, sources: Path, limit: int = 100) -> List[str]:
    missing: List[str] = []
    for entry in target.class_entries:
        # Inner and anonymous classes are emitted inside their outer class file.
        if "$" in entry:
            continue
        relative = entry[:-6] + ".java" if entry.lower().endswith(".class") else entry + ".java"
        if not (sources / relative).exists():
            missing.append(entry)
            if len(missing) >= limit:
                break
    return missing


def _input_payload(
    source: JarSource,
    info: JarInfo,
    actual: JarInfo,
    bundled_jar: Optional[str],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "path": str(source.path) if source.path is not None else source.label,
        "sha256": source.sha256(),
        "size_bytes": source.size_bytes(),
        "kind": info.kind,
        "kind_label": info.kind_label + (" (bundled)" if bundled_jar else ""),
        "loader": info.loader,
        "mc_version": info.mc_version,
        "main_class": actual.main_class,
        "class_count": actual.class_count,
        "resource_count": actual.resource_count,
        "total_uncompressed_bytes": actual.total_uncompressed_bytes,
        "signed": info.signed,
        "duplicate_entries": info.duplicate_entries[:20],
        "bundled_jar": bundled_jar,
    }
    if bundled_jar:
        payload["bundled_jar_sha256"] = actual.source.sha256()
    return payload


def _print_analysis(console: Console, analysis: Analysis) -> None:
    console.line(
        f"Analysis: {analysis.confidence}/100 confidence, {analysis.level} severity, "
        f"{'obfuscation detected' if analysis.detected else 'no strong obfuscation'}"
    )
    if analysis.detected:
        console.line(render_warning(analysis_to_dict_with_title(analysis)))
    elif analysis.level == "low":
        console.line(render_warning(analysis_to_dict_with_title(analysis)))


def analysis_to_dict_with_title(analysis: Analysis) -> Dict[str, Any]:
    payload = analysis_to_dict(analysis)
    payload["warning_title"] = analysis.warning_title
    return payload


def analyze_path(path: Path) -> Dict[str, Any]:
    """Analyze a jar without decompiling it."""
    if not path.exists():
        raise JarError(f"Input file not found: {path}")
    outer = JarSource(label=str(path), path=path)
    outer_info = inspect_jar(outer)
    target, target_info, bundled = _bundle_input(outer, outer_info)
    analysis = analyze_jar(target_info)
    return {
        "tool": {"name": "mcdc", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": _input_payload(outer, outer_info, target_info, bundled),
        "obfuscation": analysis_to_dict_with_title(analysis),
    }


def decompile_jar(
    path: Path,
    options: PipelineOptions,
    console: Optional[Console] = None,
    stem: Optional[str] = None,
) -> Dict[str, Any]:
    """Decompile one jar and write report.json / report.md beside the sources."""
    console = console or Console(quiet=options.quiet)
    if not path.exists():
        raise JarError(f"Input file not found: {path}")
    if not path.is_file():
        raise JarError(f"Input is not a file: {path}")

    console.step(1, 6, f"Reading {path.name} ({human_bytes(path.stat().st_size)})")
    source = JarSource(label=str(path), path=path)
    outer_info = inspect_jar(source)
    target_source, target_info, bundled = _bundle_input(source, outer_info)
    console.line(
        f"Kind: {outer_info.kind_label}"
        + (f" ({outer_info.loader})" if outer_info.loader else "")
        + (f" / bundled server jar: {bundled}" if bundled else "")
    )
    if outer_info.mc_version:
        console.line(f"Minecraft version: {outer_info.mc_version}")
    console.line(f"Classes: {target_info.class_count:,}")

    if target_info.class_count == 0:
        raise JarError(
            f"No class files found in {path.name}. "
            "If this is a Minecraft bundler jar, its server jar was not found."
        )

    console.step(2, 6, f"Analyzing {target_info.class_count:,} classes for obfuscation")
    analysis = analyze_jar(target_info)
    _print_analysis(console, analysis)

    output_name = stem or sanitize_stem(path.name)
    output_dir = Path(options.output_root).expanduser().resolve() / output_name
    console.step(3, 6, f"Preparing output directory {output_dir}")
    _prepare_output_dir(output_dir, options.overwrite)
    sources_dir = output_dir / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)

    java: Optional[JavaInfo] = None
    decompiler: Optional[DecompilerInfo] = None
    try:
        with tempfile.TemporaryDirectory(prefix="mcdc-classes-") as temp_name:
            classes_dir = Path(temp_name) / "classes"
            console.line(f"Extracting classes to a temporary directory...")
            extract_stats = extract_classes(
                target_source,
                target_info,
                classes_dir,
                max_total_bytes=options.max_extract_bytes,
            )
            console.line(
                f"Extracted {extract_stats.files:,} class files "
                f"({human_bytes(extract_stats.bytes)})."
            )

            console.step(4, 6, "Preparing Java and Vineflower")
            java = find_java(options.java_path)
            console.line(f"Java: {java.version} ({java.path})")
            decompiler = ensure_decompiler(
                options.decompiler_path,
                allow_download=options.allow_download,
                on_progress=lambda done, total: console.line(
                    f"Downloading Vineflower... {done * 100 // total}%"
                    if total
                    else f"Downloading Vineflower... {human_bytes(done)}"
                ),
                on_message=lambda message: console.line(message),
            )
            console.line(
                f"Vineflower: {decompiler.version} "
                f"({decompiler.source}: {decompiler.path})"
            )

            console.step(5, 6, "Decompiling classes")
            run = run_decompiler(
                java,
                decompiler,
                classes_dir,
                sources_dir,
                timeout=options.timeout,
                threads=options.threads,
                log_path=output_dir / "decompiler.log",
            )
            console.line(
                f"Decompiler finished in {human_duration(run.duration_seconds)} "
                f"with exit code {run.returncode}."
            )
    except McdcError:
        raise
    except Exception as exc:
        raise DecompilerError(f"Decompilation failed: {exc}") from exc

    java_files = _count_java(sources_dir)
    if java_files == 0:
        raise DecompilerError(
            "Vineflower did not produce any Java files. "
            f"See {output_dir / 'decompiler.log'} for details."
        )
    missing = _missing_classes(target_info, sources_dir)

    resource_stats = None
    if options.with_resources:
        console.step(6, 6, "Copying non-class resources")
        resource_stats = extract_resources(
            target_source,
            target_info,
            sources_dir,
            max_total_bytes=options.max_extract_bytes,
        )
        console.line(f"Copied {resource_stats.files:,} resource files.")
    else:
        console.step(6, 6, "Writing report")

    input_payload = _input_payload(source, outer_info, target_info, bundled)
    analysis_payload = analysis_to_dict_with_title(analysis)

    report: Dict[str, Any] = {
        "tool": {"name": "mcdc", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": input_payload,
        "obfuscation": analysis_payload,
        "decompiler": {
            "name": "Vineflower",
            "version": decompiler.version if decompiler else "unknown",
            "path": str(decompiler.path) if decompiler else "",
            "java": java.path if java else "",
            "java_version": java.version if java else "",
            "threads": options.threads or min(8, max(1, os.cpu_count() or 4)),
            "duration_seconds": round(run.duration_seconds, 3),
            "return_code": run.returncode,
        },
        "output": {
            "root": str(output_dir),
            "sources_dir": str(sources_dir),
            "report_json": str(output_dir / "report.json"),
            "report_md": str(output_dir / "report.md"),
            "decompiler_log": str(output_dir / "decompiler.log"),
            "java_files": java_files,
            "class_files": target_info.class_count,
            "missing_classes": missing,
            "resource_files": resource_stats.files if resource_stats else 0,
            "resources_included": options.with_resources,
        },
        "warnings": analysis_payload.get("advice", []) if analysis.detected else [],
        "notes": list(analysis_payload.get("notes", [])),
    }

    if missing:
        report["notes"].append(
            f"{len(missing)} class file(s) produced no matching .java file. "
            "The decompiler log may contain details."
        )

    report_json = output_dir / "report.json"
    report_md = output_dir / "report.md"
    with report_json.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    report_md.write_text(render_markdown(report), encoding="utf-8")

    console.line("")
    console.line(f"Sources: {sources_dir}")
    console.line(f"Report:  {report_md}")
    console.line(
        f"Done: {java_files:,} Java files from {target_info.class_count:,} classes "
        f"in {human_duration(run.duration_seconds)}."
    )
    if analysis.detected:
        console.warning(
            f"WARNING: Obfuscation was detected (confidence {analysis.confidence}/100). "
            "See the report before relying on these names."
        )
    return report
