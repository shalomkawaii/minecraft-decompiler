"""Java and Vineflower management plus decompiler process execution."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

from . import __version__
from .errors import DecompilerError, JavaError
from .jarinfo import parse_manifest
from .util import human_bytes, parse_java_major, parse_java_version_line, sha256_file

VINEFLOWER_VERSION = "1.12.0"
VINEFLOWER_SHA256 = "1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d"
VINEFLOWER_URL = (
    "https://github.com/Vineflower/vineflower/releases/download/"
    f"{VINEFLOWER_VERSION}/vineflower-{VINEFLOWER_VERSION}.jar"
)
VINEFLOWER_MIN_JAVA = 17
MAX_LOG_BYTES = 2 * 1024 * 1024

ProgressCallback = Callable[[int, int], None]
MessageCallback = Callable[[str], None]


@dataclass
class JavaInfo:
    path: str
    version: str
    major: int


@dataclass
class DecompilerInfo:
    path: Path
    version: str
    source: str  # "cache", "explicit", "environment"


@dataclass
class DecompileRun:
    command: Tuple[str, ...]
    returncode: int
    duration_seconds: float
    log: str
    timed_out: bool


def cache_dir() -> Path:
    override = os.environ.get("MCDC_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "mcdc" / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "mcdc"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mcdc"


def cached_decompiler_path() -> Path:
    return cache_dir() / f"vineflower-{VINEFLOWER_VERSION}.jar"


def find_java(explicit: Optional[str] = None) -> JavaInfo:
    """Locate Java and verify that it is new enough for Vineflower."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env_java = os.environ.get("MCDC_JAVA")
    if env_java:
        candidates.append(env_java)
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        executable = "java.exe" if os.name == "nt" else "java"
        candidates.append(str(Path(java_home) / "bin" / executable))
    discovered = shutil.which("java")
    if discovered:
        candidates.append(discovered)

    errors = []
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_dir():
            executable = "java.exe" if os.name == "nt" else "java"
            path = path / "bin" / executable
        if not path.exists():
            errors.append(f"{candidate} does not exist")
            continue
        try:
            result = subprocess.run(
                [str(path), "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        output = result.stdout or ""
        major = parse_java_major(output)
        if result.returncode != 0:
            errors.append(f"{path}: java -version failed")
            continue
        if major is not None and major < VINEFLOWER_MIN_JAVA:
            raise JavaError(
                f"Java {major} found at {path}, but Vineflower {VINEFLOWER_VERSION} "
                f"requires Java {VINEFLOWER_MIN_JAVA} or newer. Install a newer JDK or set "
                "JAVA_HOME / MCDC_JAVA."
            )
        return JavaInfo(
            path=str(path),
            version=parse_java_version_line(output),
            major=major or 0,
        )

    detail = "; ".join(errors) if errors else "no java executable found on PATH"
    raise JavaError(
        "Java 17 or newer is required to run Vineflower. "
        f"Details: {detail}. Install a JDK and try again."
    )


def _version_from_manifest(path: Path) -> Optional[str]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            data = zf.read("META-INF/MANIFEST.MF")
        manifest = parse_manifest(data)
        for key in ("Implementation-Version", "Bundle-Version", "Specification-Version"):
            value = manifest.get(key)
            if value:
                return value
    except (OSError, KeyError, zipfile.BadZipFile):
        return None
    return None


def decompiler_info(path: Path, source: str) -> DecompilerInfo:
    version = _version_from_manifest(path)
    if not version:
        name = path.name
        if name.startswith("vineflower-"):
            version = name[len("vineflower-") :].replace("-slim", "").replace(".jar", "")
        else:
            version = "unknown"
    return DecompilerInfo(path=path, version=version, source=source)


def _download(
    destination: Path,
    on_progress: Optional[ProgressCallback] = None,
    on_message: Optional[MessageCallback] = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(
        VINEFLOWER_URL,
        headers={"User-Agent": f"mcdc/{__version__} (+https://github.com/shalomkawaii/minecraft-decompiler)"},
    )
    downloaded = 0
    total = 0
    last_reported = -1
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            length = response.headers.get("Content-Length")
            total = int(length) if length and length.isdigit() else 0
            if on_message:
                size_text = f" ({human_bytes(total)})" if total else ""
                on_message(f"Downloading Vineflower {VINEFLOWER_VERSION}{size_text}...")
            with temporary.open("wb") as handle:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    downloaded += len(chunk)
                    if on_progress:
                        if total:
                            percent = int(downloaded * 100 / total)
                            if percent >= last_reported + 10 or downloaded == total:
                                last_reported = percent
                                on_progress(downloaded, total)
                        elif downloaded // (1024 * 1024) > last_reported:
                            last_reported = downloaded // (1024 * 1024)
                            on_progress(downloaded, 0)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise DecompilerError(
            "Could not download Vineflower. Check your network connection, or download "
            f"{VINEFLOWER_URL} manually and pass it with --decompiler PATH."
        ) from exc

    actual = sha256_file(temporary)
    if actual.lower() != VINEFLOWER_SHA256.lower():
        try:
            temporary.unlink()
        except OSError:
            pass
        raise DecompilerError(
            "The downloaded Vineflower jar failed SHA-256 verification. "
            "Delete the cache and retry, or pass --decompiler PATH with a trusted copy."
        )
    os.replace(temporary, destination)


def ensure_decompiler(
    explicit: Optional[str] = None,
    allow_download: bool = True,
    on_progress: Optional[ProgressCallback] = None,
    on_message: Optional[MessageCallback] = None,
) -> DecompilerInfo:
    """Return a verified Vineflower jar, downloading it if necessary."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise DecompilerError(
                f"Decompiler jar not found: {path}. Download it from {VINEFLOWER_URL}."
            )
        if path.is_dir():
            raise DecompilerError(f"Decompiler path is a directory, not a jar: {path}")
        return decompiler_info(path, "explicit")

    env_path = os.environ.get("MCDC_VINEFLOWER_JAR")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.exists():
            raise DecompilerError(f"MCDC_VINEFLOWER_JAR does not exist: {path}")
        return decompiler_info(path, "environment")

    cached = cached_decompiler_path()
    if cached.exists():
        if sha256_file(cached).lower() == VINEFLOWER_SHA256.lower():
            return decompiler_info(cached, "cache")
        if not allow_download:
            raise DecompilerError(
                f"Cached Vineflower jar is corrupt: {cached}. Delete it and retry."
            )
        try:
            cached.unlink()
        except OSError as exc:
            raise DecompilerError(f"Cannot replace corrupt cache file {cached}: {exc}") from exc

    if not allow_download:
        raise DecompilerError(
            "Vineflower is not cached and downloads are disabled. Download "
            f"{VINEFLOWER_URL} and pass it with --decompiler PATH."
        )

    _download(cached, on_progress=on_progress, on_message=on_message)
    return decompiler_info(cached, "cache")


def _kill_tree(process: subprocess.Popen) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def _tail(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return "...\n" + text[-limit:]


def run_decompiler(
    java: JavaInfo,
    decompiler: DecompilerInfo,
    input_dir: Path,
    output_dir: Path,
    timeout: int = 900,
    threads: int = 0,
    log_path: Optional[Path] = None,
) -> DecompileRun:
    """Run Vineflower on a directory of classes and capture its log."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if threads <= 0:
        threads = min(8, max(1, os.cpu_count() or 4))
    command = [
        java.path,
        "-jar",
        str(decompiler.path),
        "--folder",
        "--skip-extra-files=1",
        "--log-level=warn",
        f"--thread-count={threads}",
        str(input_dir),
        str(output_dir),
    ]

    started = time.time()
    timed_out = False
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise DecompilerError(f"Could not start Java: {exc}") from exc

    try:
        output, _ = process.communicate(timeout=timeout if timeout > 0 else None)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(process)
        output, _ = process.communicate()
    duration = time.time() - started
    log = output or ""

    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("w", encoding="utf-8", errors="replace") as handle:
                handle.write(log[:MAX_LOG_BYTES])
                if len(log) > MAX_LOG_BYTES:
                    handle.write("\n[log truncated by mcdc]\n")
        except OSError:
            pass

    run = DecompileRun(
        command=tuple(command),
        returncode=process.returncode if process.returncode is not None else -1,
        duration_seconds=duration,
        log=log,
        timed_out=timed_out,
    )
    if timed_out:
        raise DecompilerError(
            f"Vineflower timed out after {timeout} seconds. "
            "Increase --timeout for very large jars, or decompile fewer classes."
        )
    if run.returncode != 0:
        raise DecompilerError(
            f"Vineflower failed with exit code {run.returncode}.\n{_tail(log)}"
        )
    return run
