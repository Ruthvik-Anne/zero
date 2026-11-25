"""Zero's Python deletion guard (DEL-04).

Install the audit hook before untrusted code runs. Blocked calls raise
`DeletionBlocked`, a `PermissionError` subclass, and the target is untouched.

    from zero_guard import install, DeletionBlocked
    install()

Covered: os.remove, os.unlink, os.rmdir, os.removedirs, os.truncate,
shutil.rmtree, pathlib.Path.unlink, pathlib.Path.rmdir, and overwrite-by-move
(os.replace, or os.rename/shutil.move onto an existing destination).

Not covered (documented, by design): native extensions, `ctypes`, and
absolute-path binaries that never enter the Python interpreter's audit hooks.
The trash and the overwrite journal remain the backstop.
"""

import os
import sys

__all__ = ["DeletionBlocked", "install", "is_installed"]


class DeletionBlocked(PermissionError):
    """Raised when code inside the guarded interpreter tries to delete."""


_installed = False


def _destination(path):
    try:
        return os.fspath(path)
    except TypeError:
        return None


def _hook(event, args):
    if event in ("os.remove", "os.rmdir", "os.truncate", "shutil.rmtree"):
        target = _destination(args[0]) if args else "?"
        raise DeletionBlocked(f"{event} is blocked; use the `trash` tool ({target})")
    if event in ("os.rename", "os.replace", "shutil.move"):
        if len(args) >= 2:
            destination = _destination(args[1])
            # Overwrite-by-move is a deletion of the destination's content.
            if event == "os.replace" or (destination and os.path.exists(destination)):
                raise DeletionBlocked(f"{event} onto an existing path is blocked ({destination})")


def install():
    """Install the audit hook once. Safe to call repeatedly."""
    global _installed
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True


def is_installed():
    return _installed
