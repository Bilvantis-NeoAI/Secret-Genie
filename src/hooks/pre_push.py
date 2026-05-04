#!/usr/bin/env python3
"""Pre-push hook.

Runs the secret scanner against files being pushed. If anything is flagged,
opens the SecretGenie webapp in the user's browser at the review page and
blocks the push until the user submits a justification or aborts.

There is no terminal UI any more — every interaction goes through the
webapp, whether the push was initiated from a shell, from VS Code, from
IntelliJ, or from another GUI client.

If the browser cannot be opened (truly headless CI, no `$BROWSER`, etc.),
the hook prints the URL and keeps waiting so you can paste it into any
browser on the host. If the timeout elapses without a decision, the push
is aborted.
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(message)s")

SCRIPT_DIR = Path(__file__).resolve().parent


def _bootstrap_paths() -> None:
    """Add the scanner modules and genie_cli package to sys.path.

    Supports three layouts:
      * installed:   ~/.genie/secret_scan, ~/.genie/genie_cli
      * source tree: src/hooks/scanner, src/genie_cli
      * frozen:      _MEIPASS/hooks/scanner, _MEIPASS/genie_cli
    """
    home_genie = Path.home() / ".genie"
    direct_candidates = [
        SCRIPT_DIR.parent / "secret_scan",
        SCRIPT_DIR / "scanner",
        home_genie / "secret_scan",
    ]
    package_parent_candidates = [
        home_genie,
        SCRIPT_DIR.parent.parent / "src",
        SCRIPT_DIR.parent,
    ]
    if getattr(sys, "frozen", False):
        meipass = Path(sys._MEIPASS)  # type: ignore[attr-defined]
        direct_candidates.insert(0, meipass / "hooks" / "scanner")
        package_parent_candidates.insert(0, meipass)

    for candidate in direct_candidates:
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))

    for parent in package_parent_candidates:
        if (parent / "genie_cli").exists() and str(parent) not in sys.path:
            sys.path.insert(0, str(parent))
            break


_bootstrap_paths()

from secretscan import SecretScanner, generate_html_report  # type: ignore  # noqa: E402

try:
    from scan_config import (  # type: ignore
        should_scan_diff,
        should_scan_repo,
        should_scan_changed_lines_only,
    )
except ImportError:
    def should_scan_diff() -> bool: return True
    def should_scan_repo() -> bool: return True
    def should_scan_changed_lines_only() -> bool: return True

try:
    from genie_cli.webapp import review_push
    _WEBAPP_AVAILABLE = True
except ImportError:
    _WEBAPP_AVAILABLE = False


# ---------------------------------------------------------------------------
# Plain-text output helpers. The hook's output goes to the GUI client's progress
# panel, so we keep it concise and readable without Rich/ANSI codes.
# ---------------------------------------------------------------------------


def _info(msg: str) -> None:
    print(f"·  {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"!  {msg}", file=sys.stderr)


def _error(msg: str) -> None:
    print(f"✗  {msg}", file=sys.stderr)


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    if platform.system().lower() == "windows":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# Git plumbing
# ---------------------------------------------------------------------------


def _require_git() -> None:
    try:
        _run(["git", "--version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        _error("Git is not installed or not on PATH.")
        sys.exit(1)

    name = _run(
        ["git", "config", "--global", "user.name"], capture_output=True, text=True
    ).stdout.strip()
    email = _run(
        ["git", "config", "--global", "user.email"], capture_output=True, text=True
    ).stdout.strip()
    if not name or not email:
        _error(
            'Git identity is not configured.\n'
            '  git config --global user.name "Your Name"\n'
            '  git config --global user.email "you@example.com"'
        )
        sys.exit(1)


def get_last_pushed_commit() -> str | None:
    marker = SCRIPT_DIR / ".last-pushed-commit"
    if marker.exists():
        return marker.read_text().strip() or None
    return None


def save_current_commit_as_pushed() -> None:
    try:
        head = _run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        (SCRIPT_DIR / ".last-pushed-commit").write_text(head)
    except Exception:
        pass


def get_pushed_files() -> list[str]:
    last = get_last_pushed_commit()
    try:
        if last:
            result = _run(
                ["git", "diff", "--name-only", f"{last}..HEAD"],
                capture_output=True, text=True, check=True,
            )
        else:
            result = _run(
                ["git", "ls-files"], capture_output=True, text=True, check=True
            )
        return [f for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def run_diff_scan() -> list[dict[str, Any]]:
    scanner = SecretScanner()
    files = get_pushed_files()
    if not files:
        return []
    if should_scan_changed_lines_only():
        return scanner.scan_changed_lines(files) or []
    return scanner.scan_files(files) or []


def _dedup(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int]] = set()
    out: list[dict[str, Any]] = []
    for f in findings:
        key = (str(f.get("file_path", "")), int(f.get("line_number", 0) or 0))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Approval — always via the webapp
# ---------------------------------------------------------------------------


def validate_findings(findings: list[dict[str, Any]]) -> tuple[bool, str, str]:
    if not _WEBAPP_AVAILABLE:
        _error(
            "The SecretGenie webapp is not available. Reinstall SecretGenie and retry:\n"
            "  secretgenie install"
        )
        return False, "", ""

    try:
        result = review_push(findings, printer=_info)
    except Exception as exc:
        _error(f"Review flow failed: {exc}")
        return False, "", ""

    if result.proceed:
        return True, result.justification, result.confirmation

    reason_map = {
        "aborted": "Push aborted from the browser review page.",
        "timeout": "No decision received in time; aborting push.",
        "closed":  "Review tab closed without a decision; aborting push.",
    }
    _error(reason_map.get(result.reason, "Push aborted."))
    return False, "", ""


# ---------------------------------------------------------------------------
# Side effects after approval
# ---------------------------------------------------------------------------


def save_metadata(validation_results: dict, secrets_data: list[dict]) -> None:
    metadata_file = SCRIPT_DIR / ".push_metadata.json"
    try:
        metadata_file.write_text(
            json.dumps(
                {"validation_results": validation_results, "secrets_found": secrets_data},
                indent=2,
            )
        )
    except Exception as exc:
        print(f"Warning: Failed to save metadata: {exc}", file=sys.stderr)


def record_push_information(global_message: str, files: list[str]) -> None:
    if not global_message:
        return
    log_file = SCRIPT_DIR / "push_validations.log"
    try:
        with log_file.open("a") as f:
            f.write(f"\n--- Push validation: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            f.write(f"[SECRETS] {', '.join(files)}: {global_message}\n")
    except Exception:
        pass


def append_justification_to_commit(global_message: str) -> None:
    if not global_message:
        return
    try:
        current = _run(
            ["git", "log", "-1", "--pretty=%B"],
            check=True, capture_output=True, text=True,
        ).stdout.rstrip()
        new_message = current + "\n\n[SECURITY JUSTIFICATION]\n" + global_message
        temp = SCRIPT_DIR / ".temp_commit_msg"
        temp.write_text(new_message)
        try:
            _run(["git", "commit", "--amend", "-F", str(temp)], check=True)
        finally:
            if temp.exists():
                temp.unlink()
        _info("Added security justification to commit message.")
    except Exception:
        pass


def generate_report(diff_secrets: list[dict], repo_secrets: list[dict]) -> None:
    try:
        reports_dir = SCRIPT_DIR / ".push-reports"
        reports_dir.mkdir(exist_ok=True)
        output = reports_dir / "scan-report.html"
        generate_html_report(
            str(output),
            diff_secrets=diff_secrets,
            repo_secrets=repo_secrets,
            has_secrets=bool(diff_secrets or repo_secrets),
        )
        _info(f"Report written to {output}")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    if sys.version_info[0] < 3:
        _error("Python 3 is required.")
        return 1
    _require_git()

    try:
        status = _run(
            ["git", "status", "-sb"], check=True, capture_output=True, text=True
        ).stdout.strip().lower()
        if "up to date" in status and "ahead" not in status:
            return 0
    except Exception:
        pass

    pushed_files = get_pushed_files()
    if not pushed_files:
        return 0
    _info(f"Scanning {len(pushed_files)} file(s) being pushed…")

    diff_findings: list[dict[str, Any]] = []
    repo_findings: list[dict[str, Any]] = []

    if should_scan_diff():
        diff_findings = run_diff_scan()
    if should_scan_repo():
        _info("Scanning entire repository…")
        repo_findings = SecretScanner().scan_repository() or []

    findings = _dedup(diff_findings + repo_findings)

    if not findings:
        save_metadata({}, [])
        _info("No secrets found.")
        generate_report(diff_findings, repo_findings)
        save_current_commit_as_pushed()
        return 0

    _warn(f"{len(findings)} potential secret(s) found — opening browser for review.")

    proceed, justification, confirmation = validate_findings(findings)
    if not proceed:
        return 1

    global_message = f"Justification: {justification}\nConfirmation: {confirmation}"
    validation_results = {
        "secrets": {
            "proceed": True,
            "messages": {f.get("file_path"): {"classification": "reviewed"} for f in findings},
            "global_message": global_message,
        }
    }
    save_metadata(validation_results, findings)
    record_push_information(global_message, [f.get("file_path", "?") for f in findings])
    append_justification_to_commit(global_message)
    generate_report(diff_findings, repo_findings)
    save_current_commit_as_pushed()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _error("Aborted by user.")
        sys.exit(1)
    except Exception as exc:
        _error(f"pre-push failed: {exc}")
        sys.exit(1)
