"""Shared HTML layout for all SecretGenie webapp pages."""

from __future__ import annotations

import html
from dataclasses import dataclass

from genie_cli.webapp.theme import BASE_CSS, HEARTBEAT_JS, THEME_BOOT_JS, THEME_TOGGLE_JS


@dataclass(frozen=True)
class NavItem:
    label: str
    path: str
    icon: str


# Single source of truth for the sidebar.
NAV_ITEMS: list[NavItem] = [
    NavItem("Dashboard", "/", "⌂"),
    NavItem("Scan", "/scan", "⌕"),
    NavItem("Review", "/review", "⚠"),
    NavItem("Configuration", "/config", "⚙"),
    NavItem("Exclusions", "/exclusions", "∅"),
    NavItem("Install", "/install", "↓"),
]


def render_layout(
    *,
    token: str,
    title: str,
    body: str,
    active_path: str,
    show_sidebar: bool = True,
    cwd: str = "",
    extra_js: str = "",
) -> str:
    """Wrap page `body` HTML with the shared chrome (app bar + sidebar)."""
    base_url = f"/{token}"
    nav = "".join(_render_nav_item(item, base_url, active_path) for item in NAV_ITEMS)

    sidebar = (
        f"""
        <aside class="sidebar">
            <div class="nav-section">Workspace</div>
            {nav}
        </aside>
        """
        if show_sidebar
        else ""
    )
    shell_class = "shell" if show_sidebar else "shell shell-full"

    cwd_html = (
        f'<span class="path" title="{html.escape(cwd)}">{html.escape(_shorten(cwd))}</span>'
        if cwd
        else ""
    )

    # NOTE: `window.__GENIE_BASE__` MUST be set before page body scripts run —
    # pages like the scan spinner rely on it for navigation. Scripts later in
    # the document would execute after the inline scripts inside {body}.
    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <base href="/{html.escape(token)}/">
    <title>{html.escape(title)} · SecretGenie</title>
    <script>window.__GENIE_BASE__ = {base_url!r};</script>
    <script>{THEME_BOOT_JS}</script>
    <style>{BASE_CSS}{_extra_css_for_no_sidebar()}</style>
</head>
<body>
    <header class="app-bar">
        <div class="brand">
            <span class="mark">✦</span>
            <span>SecretGenie</span>
        </div>
        {cwd_html}
        <div class="spacer"></div>
        <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" title="Toggle theme"></button>
    </header>
    <div class="{shell_class}">
        {sidebar}
        <main>{body}</main>
    </div>
    <script>{THEME_TOGGLE_JS}</script>
    <script>{HEARTBEAT_JS}</script>
    {extra_js}
</body>
</html>"""


def _render_nav_item(item: NavItem, base_url: str, active_path: str) -> str:
    full_path = f"{base_url}{item.path}" if item.path != "/" else f"{base_url}/"
    active = "active" if _matches(item.path, active_path) else ""
    return (
        f'<a class="nav-item {active}" href="{full_path}">'
        f'<span class="icon">{html.escape(item.icon)}</span>'
        f'<span>{html.escape(item.label)}</span></a>'
    )


def _matches(nav_path: str, active_path: str) -> bool:
    if nav_path == "/":
        return active_path in ("/", "", "/dashboard")
    return active_path == nav_path or active_path.startswith(nav_path + "/")


def _shorten(path: str, max_len: int = 60) -> str:
    if len(path) <= max_len:
        return path
    head, tail = path[: 12], path[-(max_len - 15):]
    return f"{head}…{tail}"


def _extra_css_for_no_sidebar() -> str:
    return """
    .shell.shell-full { grid-template-columns: 1fr; }
    """
