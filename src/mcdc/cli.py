"""Command line interface for mcdc."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import PROJECT_URL, __version__
from .decompiler import (
    VINEFLOWER_SHA256,
    VINEFLOWER_VERSION,
    cached_decompiler_path,
    cache_dir,
    decompiler_info,
    find_java,
)
from .errors import JarError, McdcError
from .extract import DEFAULT_MAX_EXTRACT_BYTES
from .jarinfo import is_valid_jar
from .pipeline import PipelineOptions, analyze_path, decompile_jar
from .reports import format_analysis, render_warning
from .util import Console, human_bytes, sanitize_stem, sha256_file

COMMANDS = {"decompile", "analyze", "doctor", "watch"}
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_STRICT = 2
EXIT_INTERRUPT = 130


def _add_decompile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        default="decompiled",
        help="Directory for generated source folders and reports (default: decompiled).",
    )
    parser.add_argument(
        "--decompiler",
        default=None,
        help="Path to a Vineflower jar. If omitted, a pinned version is downloaded and cached.",
    )
    parser.add_argument(
        "--java",
        default=None,
        help="Path to a Java 17+ executable. Defaults to JAVA_HOME or PATH.",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Never download Vineflower; fail if it is not cached.",
    )
    parser.add_argument(
        "--with-resources",
        action="store_true",
        help="Copy non-class resources (assets, metadata, data files) into the sources folder.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace a previous output directory created by mcdc.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        metavar="SECONDS",
        help="Maximum decompiler runtime (default: 900).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=0,
        metavar="N",
        help="Vineflower thread count (default: up to 8).",
    )
    parser.add_argument(
        "--max-extract-mb",
        type=int,
        default=DEFAULT_MAX_EXTRACT_BYTES // (1024 * 1024),
        metavar="MB",
        help="Maximum uncompressed bytes to extract (default: 2048).",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON reports to stdout. Progress goes to stderr.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if obfuscation is detected.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcdc",
        description=(
            "Decompile Minecraft and Java jars into source folders and detect "
            "obfuscation automatically."
        ),
        epilog=f"Project: {PROJECT_URL}",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    decompile = subparsers.add_parser(
        "decompile",
        aliases=["d"],
        help="Decompile one or more jars.",
        description="Decompile jars into <output>/<jar-name>/sources and write reports.",
    )
    decompile.add_argument("inputs", nargs="+", metavar="JAR_OR_DIR")
    _add_decompile_options(decompile)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze obfuscation without decompiling.",
        description="Analyze a jar and print a transparent obfuscation report.",
    )
    analyze.add_argument("inputs", nargs="+", metavar="JAR_OR_DIR")
    analyze.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    analyze.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON to stdout.",
    )
    analyze.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if obfuscation is detected.",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="Check Java, the decompiler cache, and the environment.",
    )
    doctor.add_argument("--json", action="store_true", help="Print JSON diagnostics.")

    watch = subparsers.add_parser(
        "watch",
        help="Watch a folder and decompile new or modified jars automatically.",
        description=(
            "Poll a folder for new or changed .jar files. Each complete jar is decompiled "
            "into the output directory. Press Ctrl+C to stop."
        ),
    )
    watch.add_argument("directory", nargs="?", default=".", metavar="DIR")
    watch.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 2).",
    )
    watch.add_argument(
        "--recursive",
        action="store_true",
        help="Watch subdirectories too.",
    )
    watch.add_argument(
        "--existing",
        action="store_true",
        help="Decompile jars that already exist when watch mode starts.",
    )
    _add_decompile_options(watch)
    return parser


def _expand_inputs(values: Sequence[str]) -> List[Path]:
    result: List[Path] = []
    seen = set()
    for value in values:
        path = Path(value).expanduser()
        if path.is_dir():
            jars = sorted(path.glob("*.jar"))
            if not jars:
                raise JarError(f"No .jar files found in directory: {path}")
            candidates = jars
        elif path.is_file():
            candidates = [path]
        else:
            raise JarError(f"Input not found: {path}")
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                result.append(candidate)
    return result


def _stems_for(paths: Sequence[Path]) -> List[str]:
    stems = [sanitize_stem(path.name) for path in paths]
    counts = Counter(stems)
    result = []
    for path, stem in zip(paths, stems):
        if counts[stem] > 1:
            digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:8]
            result.append(f"{stem}-{digest}")
        else:
            result.append(stem)
    return result


def cmd_decompile(args: argparse.Namespace) -> int:
    console = Console(quiet=args.quiet, stream=sys.stderr if args.json else sys.stdout)
    try:
        inputs = _expand_inputs(args.inputs)
    except McdcError as exc:
        console.error(str(exc))
        return EXIT_ERROR

    stems = _stems_for(inputs)
    options = PipelineOptions(
        output_root=Path(args.output),
        overwrite=args.overwrite,
        with_resources=args.with_resources,
        decompiler_path=args.decompiler,
        java_path=args.java,
        allow_download=not args.no_download,
        timeout=args.timeout,
        threads=args.threads,
        quiet=args.quiet,
        max_extract_bytes=max(1, args.max_extract_mb) * 1024 * 1024,
    )

    reports: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    any_detected = False
    for index, (path, stem) in enumerate(zip(inputs, stems)):
        if index and not args.json:
            console.line("")
        try:
            report = decompile_jar(path, options, console=console, stem=stem)
            reports.append(report)
            any_detected = any_detected or bool(report["obfuscation"].get("detected"))
        except McdcError as exc:
            errors.append({"input": str(path), "error": str(exc)})
            console.error(f"{path}: {exc}")
        except Exception as exc:
            if os.environ.get("MCDC_DEBUG"):
                raise
            errors.append({"input": str(path), "error": str(exc)})
            console.error(f"{path}: unexpected failure: {exc}")

    if args.json:
        payload: Any = reports[0] if len(reports) == 1 and not errors else reports
        if errors and not reports:
            payload = {"reports": [], "errors": errors}
        elif errors:
            payload = {"reports": reports, "errors": errors}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif errors:
        console.error(
            f"{len(errors)} input(s) failed and {len(reports)} succeeded. See messages above."
        )

    if errors:
        return EXIT_ERROR
    if args.strict and any_detected:
        return EXIT_STRICT
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    console = Console(quiet=args.quiet, stream=sys.stderr if args.json else sys.stdout)
    try:
        inputs = _expand_inputs(args.inputs)
    except McdcError as exc:
        console.error(str(exc))
        return EXIT_ERROR

    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    any_detected = False
    for path in inputs:
        try:
            result = analyze_path(path)
            results.append(result)
            any_detected = any_detected or bool(result["obfuscation"].get("detected"))
        except McdcError as exc:
            errors.append({"input": str(path), "error": str(exc)})
            console.error(f"{path}: {exc}")
        except Exception as exc:
            if os.environ.get("MCDC_DEBUG"):
                raise
            errors.append({"input": str(path), "error": str(exc)})
            console.error(f"{path}: unexpected failure: {exc}")

    if args.json:
        payload: Any = results[0] if len(results) == 1 and not errors else results
        if errors and not results:
            payload = {"results": [], "errors": errors}
        elif errors:
            payload = {"results": results, "errors": errors}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for index, result in enumerate(results):
            if index:
                console.line("")
            input_info = result["input"]
            console.line(f"Input: {input_info['path']} ({human_bytes(input_info['size_bytes'])})")
            console.line(f"Kind: {input_info['kind_label']}")
            if input_info.get("bundled_jar"):
                console.line(f"Bundled server jar: {input_info['bundled_jar']}")
            if input_info.get("mc_version"):
                console.line(f"Minecraft version: {input_info['mc_version']}")
            console.line(f"Classes: {input_info['class_count']:,}")
            analysis = result["obfuscation"]
            if analysis.get("detected"):
                console.line(format_analysis(analysis, max_reasons=0))
                console.line("")
                console.line(render_warning(analysis))
            else:
                console.line(format_analysis(analysis))
        if errors:
            console.error(f"{len(errors)} input(s) failed.")

    if errors:
        return EXIT_ERROR
    if args.strict and any_detected:
        return EXIT_STRICT
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: Dict[str, Any] = {
        "mcdc": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "java": None,
        "decompiler": None,
        "cache_dir": str(cache_dir()),
        "project": PROJECT_URL,
    }
    java_error = None
    try:
        java = find_java()
        checks["java"] = {
            "path": java.path,
            "version": java.version,
            "major": java.major,
        }
    except McdcError as exc:
        java_error = str(exc)

    cached = cached_decompiler_path()
    if cached.exists():
        valid = sha256_file(cached).lower() == VINEFLOWER_SHA256.lower()
        info = decompiler_info(cached, "cache")
        checks["decompiler"] = {
            "path": str(cached),
            "version": info.version,
            "cached": True,
            "valid": valid,
            "expected_version": VINEFLOWER_VERSION,
        }
    else:
        checks["decompiler"] = {
            "path": str(cached),
            "version": VINEFLOWER_VERSION,
            "cached": False,
            "valid": False,
            "expected_version": VINEFLOWER_VERSION,
        }

    if args.json:
        if java_error:
            checks["java_error"] = java_error
        print(json.dumps(checks, indent=2, ensure_ascii=False))
        return EXIT_ERROR if java_error else EXIT_OK

    console = Console()
    console.line(f"mcdc {__version__}")
    console.line(f"Python: {checks['python']} ({platform.machine()})")
    console.line(f"OS: {checks['platform']}")
    if java_error:
        console.line(f"Java: ERROR - {java_error}")
    else:
        console.line(f"Java: {java.version} ({java.path})")
    decompiler = checks["decompiler"]
    if decompiler["cached"]:
        status = "valid" if decompiler["valid"] else "corrupt"
        console.line(f"Vineflower: {decompiler['version']} cached at {decompiler['path']} ({status})")
    else:
        console.line(
            f"Vineflower: not cached; {VINEFLOWER_VERSION} will be downloaded on first run"
        )
    console.line(f"Cache: {checks['cache_dir']}")
    return EXIT_ERROR if java_error else EXIT_OK


def _watch_scan(directory: Path, recursive: bool) -> List[Path]:
    iterator = directory.rglob("*.jar") if recursive else directory.glob("*.jar")
    return sorted(path for path in iterator if path.is_file())


def cmd_watch(args: argparse.Namespace) -> int:
    directory = Path(args.directory).expanduser()
    if not directory.is_dir():
        raise JarError(f"Watch directory not found: {directory}")
    console = Console(quiet=args.quiet)
    options = PipelineOptions(
        output_root=Path(args.output),
        overwrite=True,
        with_resources=args.with_resources,
        decompiler_path=args.decompiler,
        java_path=args.java,
        allow_download=not args.no_download,
        timeout=args.timeout,
        threads=args.threads,
        quiet=args.quiet,
        max_extract_bytes=max(1, args.max_extract_mb) * 1024 * 1024,
    )
    interval = max(0.2, args.interval)
    seen: Dict[Path, tuple] = {}
    invalid: Dict[Path, tuple] = {}

    if args.existing:
        for path in _watch_scan(directory, args.recursive):
            seen.pop(path, None)
    console.line(f"Watching {directory.resolve()} for .jar files. Press Ctrl+C to stop.")
    if not args.existing:
        for path in _watch_scan(directory, args.recursive):
            try:
                stat = path.stat()
                seen[path] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                pass

    while True:
        for path in _watch_scan(directory, args.recursive):
            try:
                stat = path.stat()
            except OSError:
                continue
            signature = (stat.st_mtime_ns, stat.st_size)
            if seen.get(path) == signature or invalid.get(path) == signature:
                continue
            if not is_valid_jar(path):
                invalid[path] = signature
                console.line(f"Waiting for a complete jar: {path.name}")
                continue
            invalid.pop(path, None)
            console.line("")
            console.line(f"New jar detected: {path}")
            try:
                decompile_jar(
                    path,
                    options,
                    console=console,
                    stem=sanitize_stem(path.name),
                )
            except McdcError as exc:
                console.error(f"{path}: {exc}")
            except Exception as exc:
                if os.environ.get("MCDC_DEBUG"):
                    raise
                console.error(f"{path}: unexpected failure: {exc}")
            seen[path] = signature
        time.sleep(interval)


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] not in COMMANDS and not raw[0].startswith("-"):
        raw.insert(0, "decompile")
    parser = build_parser()
    args = parser.parse_args(raw)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        if args.command in ("decompile", "d"):
            return cmd_decompile(args)
        if args.command == "analyze":
            return cmd_analyze(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "watch":
            return cmd_watch(args)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return EXIT_INTERRUPT
    except McdcError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_ERROR
