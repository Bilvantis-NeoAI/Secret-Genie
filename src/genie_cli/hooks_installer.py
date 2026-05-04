"""Install / uninstall SecretGenie's Git hooks into ~/.genie."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from genie_cli.console import banner, console, err_console


HOOK_FILES = ["pre-push", "pre_push.py", "secret-scan"]
REQUIRED_FILES_IN_HOOKS_DIR = ["pre-push", "pre_push.py", "secret-scan"]

HOOK_FILE_MODE = 0o755  # rwx for owner, r-x for group/other — git hooks must be executable

_BRAND_STATUS = "[genie.brand]{}"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess; hide the console window on Windows."""
    if platform.system().lower() == "windows":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.run(cmd, **kwargs)


def _hooks_source_dir() -> Path:
    """Find the directory containing the hooks bundle (works frozen and from source)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "hooks"  # type: ignore[attr-defined]

    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "hooks",
        here.parent.parent / "src" / "hooks",
        here.parent.parent / "hooks",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _user_paths() -> dict[str, Path]:
    home = Path.home()
    genie = home / ".genie"
    return {
        "home": home,
        "genie": genie,
        "hooks": genie / "hooks",
        "secret_scan": genie / "secret_scan",
        "genie_cli": genie / "genie_cli",
        "config_file": genie / "secret_scan" / "config",
    }


def _genie_cli_source_dir() -> Path | None:
    """Locate the genie_cli package source to ship alongside the hook files."""
    if getattr(sys, "frozen", False):
        candidate = Path(sys._MEIPASS) / "genie_cli"  # type: ignore[attr-defined]
        return candidate if candidate.exists() else None
    here = Path(__file__).resolve().parent
    return here if here.name == "genie_cli" else None


def _git_installed() -> bool:
    try:
        result = _run(["git", "--version"], capture_output=True, check=False, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _git_identity() -> tuple[str, str]:
    name = _run(
        ["git", "config", "--global", "user.name"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()
    email = _run(
        ["git", "config", "--global", "user.email"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()
    return name, email


def check_prerequisites() -> list[str]:
    """Return a list of human-readable error messages, empty if all good."""
    errors: list[str] = []

    if sys.version_info < (3, 9):
        errors.append(
            f"Python 3.9+ required (you have {sys.version.split()[0]})."
        )

    if not _git_installed():
        errors.append("Git is not installed or not on PATH.")
        return errors

    name, email = _git_identity()
    if not name:
        errors.append(
            'Git user.name is not set. Run: git config --global user.name "Your Name"'
        )
    if not email:
        errors.append(
            'Git user.email is not set. Run: git config --global user.email "you@example.com"'
        )

    return errors


def is_installed() -> bool:
    """Return True if all hook files are present under ~/.genie."""
    paths = _user_paths()
    if not paths["secret_scan"].exists():
        return False
    return all((paths["hooks"] / f).exists() for f in REQUIRED_FILES_IN_HOOKS_DIR)


def status_table() -> Table:
    paths = _user_paths()
    installed = is_installed()

    table = Table(title="SecretGenie status", title_style="genie.brand", expand=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Installed", "[genie.ok]yes[/]" if installed else "[genie.danger]no[/]")
    table.add_row("Hooks directory", f"[genie.path]{paths['hooks']}[/]")
    table.add_row("Scan config dir", f"[genie.path]{paths['secret_scan']}[/]")

    hooks_path_cfg = _run(
        ["git", "config", "--global", "core.hooksPath"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()
    table.add_row("git core.hooksPath", f"[genie.path]{hooks_path_cfg or '(unset)'}[/]")

    name, email = _git_identity()
    table.add_row("git user.name", name or "[genie.danger](unset)[/]")
    table.add_row("git user.email", email or "[genie.danger](unset)[/]")

    return table


def install() -> bool:
    """Install Git hooks into ~/.genie and wire up global git aliases."""
    console.print(Panel.fit(f"{banner()} — installing hooks", border_style="genie.brand"))

    errors = check_prerequisites()
    if errors:
        for msg in errors:
            err_console.print(f"[genie.danger]✗[/] {msg}")
        return False

    hooks_source = _hooks_source_dir()
    if not hooks_source.exists():
        err_console.print(f"[genie.danger]✗[/] Hooks bundle not found at {hooks_source}")
        return False

    paths = _user_paths()

    if is_installed():
        console.print("[genie.ok]✓[/] Hooks already installed.")
        console.print(
            "  To reinstall: [genie.kbd] genie uninstall [/] then [genie.kbd] genie install [/]"
        )
        return True

    paths["genie"].mkdir(parents=True, exist_ok=True)

    if paths["hooks"].exists():
        shutil.rmtree(paths["hooks"])
    if paths["secret_scan"].exists():
        shutil.rmtree(paths["secret_scan"])
    if paths["genie_cli"].exists():
        shutil.rmtree(paths["genie_cli"])

    paths["hooks"].mkdir(parents=True)
    paths["secret_scan"].mkdir(parents=True)

    with console.status(_BRAND_STATUS.format("Copying hook files...")):
        for name in HOOK_FILES:
            src = hooks_source / name
            if src.exists():
                dst = paths["hooks"] / name
                shutil.copy2(src, dst)
                os.chmod(dst, HOOK_FILE_MODE)

        scanner_src = hooks_source / "scanner"
        if scanner_src.exists():
            shutil.copytree(scanner_src, paths["secret_scan"], dirs_exist_ok=True)

        tracker_src = hooks_source / "installation_tracker.py"
        if tracker_src.exists():
            shutil.copy2(tracker_src, paths["secret_scan"] / "installation_tracker.py")

        # Ship the genie_cli package so pre_push.py can reach browser_review +
        # the Textual findings TUI without requiring the source checkout.
        genie_cli_src = _genie_cli_source_dir()
        if genie_cli_src is not None:
            shutil.copytree(
                genie_cli_src,
                paths["genie_cli"],
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )

    with console.status(_BRAND_STATUS.format("Configuring Git...")):
        _run(["git", "config", "--global", "core.hooksPath", str(paths["hooks"])], check=True)

        secret_scan_cmd = f'!bash "{paths["hooks"] / "secret-scan"}"'
        genie_cli_cmd = f"!{sys.executable} -m genie_cli"

        _run(["git", "config", "--global", "alias.secret-scan", secret_scan_cmd], check=True)
        _run(["git", "config", "--global", "alias.genie", genie_cli_cmd], check=False)

    _write_config_marker(paths["config_file"], installed=True)

    _record_tracker_event("install", paths["secret_scan"])

    console.print("[genie.ok]✓[/] Hooks installed.")
    console.print(f"  Hooks live at [genie.path]{paths['hooks']}[/]")
    console.print(
        "  Open the dashboard with [genie.kbd] secretgenie [/] — or configure with [genie.kbd] secretgenie config [/]"
    )
    return True


def uninstall() -> bool:
    """Remove SecretGenie's aliases and scan_scripts. Leaves core.hooksPath untouched."""
    console.print(Panel.fit(f"{banner()} — uninstalling hooks", border_style="genie.brand"))

    paths = _user_paths()

    with console.status(_BRAND_STATUS.format("Removing git aliases...")):
        for alias in ("scan-repo", "scan-config", "secret-scan", "genie"):
            _run(
                ["git", "config", "--global", "--unset", f"alias.{alias}"],
                check=False, capture_output=True,
            )

    _record_tracker_event("uninstall", paths["secret_scan"])

    if paths["secret_scan"].exists():
        shutil.rmtree(paths["secret_scan"])
        console.print(f"  Removed [genie.path]{paths['secret_scan']}[/]")

    if paths["genie_cli"].exists():
        shutil.rmtree(paths["genie_cli"])
        console.print(f"  Removed [genie.path]{paths['genie_cli']}[/]")

    console.print("[genie.ok]✓[/] Uninstalled.")
    console.print(
        "  [genie.muted]core.hooksPath was preserved so other tools keep working.[/]"
    )
    return True


def _write_config_marker(config_file: Path, *, installed: bool) -> None:
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(f"installed={'true' if installed else 'false'}\n")


def _record_tracker_event(event: str, secret_scan_path: Path) -> None:
    """Best-effort call into installation_tracker. Silences the tracker's own
    log handler so we don't leak ERROR lines about missing GITHUB_PAT."""
    import logging

    original_level = logging.root.level
    logging.disable(logging.CRITICAL)
    try:
        sys.path.insert(0, str(secret_scan_path))
        if event == "install":
            from installation_tracker import record_installation  # type: ignore
            record_installation()
        elif event == "uninstall":
            from installation_tracker import record_uninstallation  # type: ignore
            record_uninstallation()
    except Exception:
        pass
    finally:
        logging.disable(logging.NOTSET)
        logging.root.setLevel(original_level)
