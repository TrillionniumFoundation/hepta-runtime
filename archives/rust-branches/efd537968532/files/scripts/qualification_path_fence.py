"""Reject executable search paths that can launch unreviewed source programs.

This protects source qualification from relative PATH entries and entries that
resolve inside a checked source tree. It is not a general-purpose host sandbox:
the operator must still trust system executables and the host filesystem.
"""

from __future__ import annotations

import os
from pathlib import Path


class UnsafeCommandPath(ValueError):
    """A PATH entry could load a command from outside the reviewed toolchain."""


def check_command_search_path(path: str | None, source_root: Path | None = None) -> None:
    """Validate PATH before any Git, Rust, or Python process is spawned.

    Every entry must be absolute and nonempty. No entry may resolve to or
    below the source root, including via a directory symlink. Resolution is
    a validation guard, not an atomic pin against a malicious host admin.
    """
    if not path:
        raise UnsafeCommandPath("missing executable PATH")
    try:
        root = source_root.resolve(strict=True) if source_root is not None else None
    except (OSError, RuntimeError) as exc:
        raise UnsafeCommandPath("cannot resolve qualification source root") from exc
    for entry in path.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            raise UnsafeCommandPath("PATH contains an empty or relative search entry")
        try:
            directory = Path(entry).resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise UnsafeCommandPath("cannot resolve executable PATH entry") from exc
        if root is not None and (directory == root or root in directory.parents):
            raise UnsafeCommandPath("PATH searches inside unreviewed source tree")
