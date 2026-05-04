"""Shared Rich console and theme for SecretGenie."""

import sys

from rich.console import Console
from rich.theme import Theme

# Python on Windows still defaults stdout/stderr to the legacy ANSI code page
# (cp1252 for en-US installs). Our banner uses the '✦' (U+2726) glyph, which
# can't round-trip through cp1252 and blows up Rich's legacy_windows_render
# path with UnicodeEncodeError on every CLI invocation. Force UTF-8 here so
# the CLI works regardless of the active code page. Safe on non-Windows and
# on already-UTF-8 streams; no-ops if reconfigure isn't available (e.g.
# redirected output or exotic stream wrappers).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        pass

GENIE_THEME = Theme(
    {
        "genie.brand": "bold #5a9bff",
        "genie.accent": "bold #c792ea",
        "genie.ok": "bold #50fa7b",
        "genie.warn": "bold #ffd866",
        "genie.danger": "bold #ff6e6e",
        "genie.muted": "dim",
        "genie.path": "#8be9fd",
        "genie.kbd": "reverse #f8f8f2",
    }
)


console = Console(theme=GENIE_THEME, highlight=False)
err_console = Console(theme=GENIE_THEME, highlight=False, stderr=True)


def banner() -> str:
    """Compact brand banner used in CLI headers."""
    return "[genie.brand]✦ SecretGenie[/]"
