"""Shared Rich console and theme for SecretGenie."""

from rich.console import Console
from rich.theme import Theme

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
