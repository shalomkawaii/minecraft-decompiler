# mcdc

**Decompile Minecraft JARs into a source folder. Get a warning when the jar is obfuscated.**

`mcdc` is a small, dependency-free Python CLI around [Vineflower](https://github.com/Vineflower/vineflower). It handles official client and server jars, modern bundled server jars, mods, and ordinary Java jars. Obfuscation detection runs before decompilation, and the result is written to a readable report next to the sources.

No game files are included in this repository. `mcdc` only downloads Vineflower and processes jars you give it.

[![CI](https://github.com/shalomkawaii/minecraft-decompiler/actions/workflows/ci.yml/badge.svg)](https://github.com/shalomkawaii/minecraft-decompiler/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Vineflower 1.12.0](https://img.shields.io/badge/Vineflower-1.12.0-orange.svg)](https://github.com/Vineflower/vineflower/releases/tag/1.12.0)

## Why mcdc

- **One command.** `mcdc decompile server.jar` produces a complete source tree.
- **Automatic obfuscation warning.** No guessing whether `a.java`, `aa.java`, and `aaa.java` are normal.
- **Minecraft aware.** Detects client, server, bundled server, Fabric, Quilt, Forge, and NeoForge jars.
- **Modern server jars work.** The 1.18+ `server.jar` is a bundler; `mcdc` finds and decompiles the inner server jar automatically.
- **Safe by default.** Guarded extraction, zip-bomb limits, no execution of the input jar, and a pinned Vineflower download verified with SHA-256.
- **Useful output.** A source folder, `report.json`, `report.md`, and `decompiler.log`.
- **Automation friendly.** JSON output, stable exit codes, and a folder watcher.
- **Zero Python dependencies.**

## Quick start

Requirements: **Python 3.9+** and **Java 17+**. Java 21 is recommended.

```bash
git clone https://github.com/shalomkawaii/minecraft-decompiler.git
cd minecraft-decompiler
python -m pip install .

mcdc decompile server.jar
```

Or install with pipx:

```bash
pipx install git+https://github.com/shalomkawaii/minecraft-decompiler.git
mcdc decompile server.jar
```

On Windows, `py -m pip install .` works if `python` is not on PATH.

The first run downloads Vineflower 1.12.0 (about 1.6 MiB) into the user cache and verifies its SHA-256. Later runs are offline unless you ask for a different decompiler.

## What you get

```text
decompiled/
  server-1.20.4/
    sources/
      a.java
      aa.java
      net/
      ...
    report.md
    report.json
    decompiler.log
```

Use `--with-resources` to copy non-class files such as `assets/`, `data/`, `fabric.mod.json`, and loader metadata into `sources/` as well.

A real warning from an obfuscated Minecraft 1.20.4 server jar:

```text
==============================================================================
 WARNING: OBFUSCATED MINECRAFT JAR DETECTED
 Confidence: 53/100 (medium)
==============================================================================

This looks like an official Minecraft jar. Decompiled names will be Mojang's
obfuscated names (a, b, c, ...). Use official mappings if you need readable
names.

Do not redistribute decompiled Minecraft game code. Decompile only jars you
are allowed to inspect.

Signals:
 - 99.6% of classes have names with three characters or fewer.
 - 99.6% of classes are in the default package.

==============================================================================
```

The same tool recognizes a deobfuscated build. Recent Minecraft server jars can ship with readable names and debug information; in that case `mcdc` reports that no obfuscation was detected instead of inventing a warning.

## Usage

```bash
# Decompile one jar, or several at once
mcdc decompile server.jar client.jar

# Choose the output root (default: ./decompiled)
mcdc decompile server.jar -o ~/mc-sources

# Include assets, data files, and mod metadata
mcdc decompile server.jar --with-resources

# Analyze without decompiling
mcdc analyze server.jar

# Machine-readable analysis
mcdc analyze server.jar --json

# Decompile and fail CI when obfuscation is detected (exit code 2)
mcdc decompile server.jar --strict

# Watch a downloads folder and decompile new jars as they arrive
mcdc watch ~/Downloads --existing

# Check Java and the decompiler cache
mcdc doctor
```

`mcdc <jar>` is shorthand for `mcdc decompile <jar>`.

### Options

| Option | Meaning |
| --- | --- |
| `-o, --output DIR` | Output root for source folders and reports. Default: `decompiled`. |
| `--with-resources` | Copy assets, data, and metadata into `sources/`. |
| `--overwrite` | Replace a previous output directory created by mcdc. |
| `--decompiler PATH` | Use a specific Vineflower jar instead of the cached download. |
| `--java PATH` | Use a specific Java 17+ executable. |
| `--no-download` | Fail instead of downloading Vineflower. |
| `--timeout SECONDS` | Decompiler timeout. Default: `900`. |
| `--threads N` | Vineflower thread count. Default: up to 8. |
| `--max-extract-mb MB` | Maximum uncompressed bytes to extract. Default: `2048`. |
| `--json` | Print a JSON report to stdout; progress goes to stderr. |
| `--strict` | Exit with code `2` when obfuscation is detected. |
| `--quiet` | Suppress progress output. |

Environment variables:

| Variable | Meaning |
| --- | --- |
| `MCDC_JAVA` | Java executable to use. |
| `MCDC_VINEFLOWER_JAR` | Vineflower jar to use. |
| `MCDC_CACHE_DIR` | Cache directory for the downloaded decompiler. |
| `MCDC_DEBUG` | Re-raise unexpected exceptions with a traceback. |

Exit codes: `0` success, `1` error, `2` strict obfuscation failure, `130` interrupted.

## Obfuscation detection

`mcdc` parses class files directly to collect:

- class and package name structure;
- `SourceFile` and `LineNumberTable` debug attributes;
- synthetic and inner-class ratios;
- known obfuscator marker strings in the constant pool;
- bundled ProGuard configuration files;
- informational hardening signals such as instrumentation, reflection, native loading, and cryptography.

Signals are weighted and explained. The score is intentionally transparent:

| Confidence | Level | Behavior |
| --- | --- | --- |
| `0-19` | none | No warning. |
| `20-44` | low | A short note, no warning banner. |
| `45-69` | medium | Warning banner. |
| `70-100` | high | Warning banner. |

A warning means "the names and debug information look obfuscated". It does **not** mean the jar is malicious. Obfuscation is common in legitimate mods and libraries. The report includes the raw metrics so you can make your own call.

Known obfuscator names and hardening strings are hints, not proof. The README for `report.md` lists every signal that contributed to the score.

### Minecraft-specific behavior

- **Official client/server jars:** detected from `Main-Class`, `net/minecraft/client/main/Main.class`, and `net/minecraft/server/MinecraftServer.class`.
- **Bundled server jars:** `META-INF/versions/<version>/server-<version>.jar` is extracted in memory and decompiled. The outer bundler jar is never mistaken for the game code.
- **Mods:** Fabric, Quilt, Forge, and NeoForge metadata is detected. Obfuscated third-party mods get a corresponding warning.
- **Deobfuscated builds:** if the jar already has readable names and line numbers, no obfuscation warning is produced.

## How it works

1. Read the jar and detect its kind, version, loader, signature, and nested server jar.
2. Parse every class file and compute the obfuscation score.
3. Extract class entries into a temporary directory with path-traversal and size guards.
4. Run Vineflower in folder mode against the extracted classes.
5. Optionally copy non-class resources.
6. Write `report.json`, `report.md`, and `decompiler.log` next to `sources/`.

The input jar is treated as data. `mcdc` never runs its `Main-Class`, never loads classes, and never executes build scripts from it.

## Safety and legal notes

- This project contains no Minecraft code, mappings, or assets.
- Decompile only jars you are allowed to inspect. Minecraft is property of Mojang Studios and Microsoft; the Minecraft EULA and local law still apply.
- Do not redistribute decompiled game code.
- Obfuscation detection is a heuristic, not a malware scanner. Never run an untrusted jar, even if `mcdc` reports "no obfuscation".
- Vineflower is downloaded at runtime under its own [Apache-2.0 license](https://github.com/Vineflower/vineflower/blob/master/LICENSE).

`mcdc` is not affiliated with Mojang, Microsoft, or the Vineflower project.

## Development

```bash
git clone https://github.com/shalomkawaii/minecraft-decompiler.git
cd minecraft-decompiler
python -m pip install -e .

# Unit tests (compile small Java fixtures, no network)
python -m unittest discover -s tests -v

# End-to-end test with the real decompiler (downloads Vineflower once)
MCDC_RUN_E2E=1 python -m unittest tests.test_e2e -v
```

The test suite builds its own tiny jars with `javac`, including obfuscated-name, clean, official-Minecraft-pattern, and bundler fixtures. No binary fixtures are committed.

CI runs the unit suite on Ubuntu, Windows, and macOS across Python 3.9, 3.12, and 3.13, plus a Vineflower end-to-end job on Linux.

## Roadmap

- Optional application of official Mojang mappings to turn `a`, `aa`, `aaa` into readable names before writing sources.
- Class filters for decompiling a single package or entry point.
- Parallel batch decompilation with a shared report index.
- A container image and a single-file executable for users without Python.

## License

MIT. See [LICENSE](LICENSE).
