"""SecretGenie CLI.

Almost all user-facing work happens in the local browser webapp. The CLI exists
for two reasons: launch the webapp at the right landing page, and provide
non-interactive (`--auto`, `--json`) entry points for CI and automation.

Commands:
    secretgenie                    → open the dashboard in a browser
    secretgenie install            → open the install wizard
    secretgenie install --auto     → install silently (for CI / Dockerfiles)
    secretgenie uninstall --auto   → uninstall silently
    secretgenie scan               → open the scan page and run a scan
    secretgenie scan --json        → scan and emit JSON findings (for CI gates)
    secretgenie config             → open the configuration page
"""

from __future__ import annotations

import json as _json
import os
import sys
from pathlib import Path

import typer

from genie_cli import __version__
from genie_cli.console import banner, console, err_console


app = typer.Typer(
    name="genie",
    help="SecretGenie — scan Git repos for secrets. Runs as a local browser app.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _print_version(value: bool) -> None:
    if value:
        console.print(f"{banner()} [genie.muted]v{__version__}[/]")
        raise typer.Exit(0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=_print_version, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Default action: open the dashboard in a browser."""
    if ctx.invoked_subcommand is not None:
        return
    _launch("/")


@app.command("install")
def cmd_install(
    auto: bool = typer.Option(
        False, "--auto",
        help="Install silently without opening the browser (for CI / provisioning).",
    ),
) -> None:
    """Install SecretGenie's Git hooks."""
    if auto:
        from genie_cli.hooks_installer import install as do_install
        ok = do_install()
        raise typer.Exit(0 if ok else 1)
    _launch("/install")


@app.command("uninstall")
def cmd_uninstall(
    auto: bool = typer.Option(
        False, "--auto",
        help="Uninstall silently without opening the browser.",
    ),
) -> None:
    """Remove SecretGenie's Git hooks and aliases."""
    if auto:
        from genie_cli.hooks_installer import uninstall as do_uninstall
        ok = do_uninstall()
        raise typer.Exit(0 if ok else 1)
    _launch("/install")


@app.command("scan")
def cmd_scan(
    as_json: bool = typer.Option(
        False, "--json",
        help="Emit findings as JSON to stdout and exit (for CI gates).",
    ),
) -> None:
    """Scan the current repository for secrets.

    Always runs a full repository scan. The scan-mode setting in the
    configuration page governs only the pre-push hook, not manual scans.
    """
    if as_json:
        _run_cli_scan()
        return
    _launch("/scan/run")


@app.command("config")
def cmd_config() -> None:
    """Open the configuration page in the browser."""
    _launch("/config")


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _launch(landing: str) -> None:
    """Start the webapp and block until the user closes the tab or Ctrl-C."""
    try:
        from genie_cli.webapp import launch
    except Exception as exc:
        err_console.print(f"[genie.danger]Could not start the webapp:[/] {exc}")
        raise typer.Exit(1)

    try:
        launch(landing=landing, cwd=os.getcwd(), printer=console.print)
    except KeyboardInterrupt:
        console.print("\n[genie.muted]Stopped.[/]")


def _run_cli_scan() -> None:
    """Non-interactive full-repo scan that prints JSON findings to stdout.

    Uses the same robust runner as the webapp — parallel, resilient to bad
    files, safe against oversized / binary / weirdly-encoded files.

    Exit codes: 0 = no findings, 1 = findings, 2 = error.
    """
    _ensure_scanner_on_path()
    try:
        from genie_cli.webapp.scan_runner import ScanProgress, scan_repository_robust
    except Exception as exc:
        err_console.print(f"[genie.danger]Scanner not available:[/] {exc}")
        raise typer.Exit(2)

    progress = ScanProgress()
    try:
        findings = scan_repository_robust(progress=progress)
    except Exception as exc:
        err_console.print(f"[genie.danger]Scan failed:[/] {exc}")
        raise typer.Exit(2)

    if progress.error:
        err_console.print(f"[genie.danger]Scan error:[/] {progress.error}")
        raise typer.Exit(2)

    sys.stdout.write(_json.dumps({
        "findings": findings,
        "stats": progress.to_dict(),
    }) + "\n")
    raise typer.Exit(1 if findings else 0)


def _ensure_scanner_on_path() -> None:
    candidates = [
        Path.home() / ".genie" / "secret_scan",
        Path(__file__).resolve().parent.parent / "hooks" / "scanner",
    ]
    for candidate in candidates:
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))


if __name__ == "__main__":
    app()
