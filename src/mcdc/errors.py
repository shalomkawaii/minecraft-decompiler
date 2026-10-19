"""Errors shown to users without a Python traceback."""

from __future__ import annotations


class McdcError(Exception):
    """Base class for expected, user-facing failures."""


class JarError(McdcError):
    """The input cannot be read as a Java archive."""


class ClassFormatError(McdcError):
    """A class file is malformed or truncated."""


class ExtractionError(McdcError):
    """An archive entry cannot be extracted safely."""


class JavaError(McdcError):
    """Java is missing, too old, or failed to start."""


class DecompilerError(McdcError):
    """Vineflower could not be prepared or failed while running."""


class OutputError(McdcError):
    """The output directory cannot be created or safely replaced."""
