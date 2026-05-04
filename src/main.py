"""SecretGenie entry point.

Historically this was a PySide6 GUI; it is now a thin shim that
dispatches to the `genie_cli` Typer app so PyInstaller builds and
`python src/main.py ...` both still work.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_sys_path() -> None:
    """Make sure `genie_cli` is importable when running from source."""
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))


def _translate_legacy_flags(argv: list[str]) -> list[str]:
    """Map the old /install, /uninstall, --install slash-flags onto Typer subcommands."""
    mapping = {
        "/install": "install",
        "-install": "install",
        "--install": "install",
        "/uninstall": "uninstall",
        "-uninstall": "uninstall",
        "--uninstall": "uninstall",
        "/help": "--help",
        "/?": "--help",
    }
    out: list[str] = []
    for arg in argv:
        out.append(mapping.get(arg.lower(), arg))
    return out


def main() -> None:
    _bootstrap_sys_path()
    from genie_cli.cli import app

    sys.argv = [sys.argv[0]] + _translate_legacy_flags(sys.argv[1:])
    app()


if __name__ == "__main__":
    main()
