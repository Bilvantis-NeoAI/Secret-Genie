"""Ephemeral local webapp server for SecretGenie.

Each command (`secretgenie`, `install`, `scan`, `config`, `review`) spins up one
of these servers, opens the browser at the right landing page, and exits when
the user closes the tab (detected via sendBeacon) or after an idle timeout.

Modes:
    AppMode.INTERACTIVE  — dashboard + all navigation. Used by `secretgenie`,
                           `install`, `scan`, `config`. The server stays up while
                           the user is on the page and shuts down when the tab
                           closes or after a long idle timeout.
    AppMode.REVIEW       — single-purpose approval flow for the pre-push hook.
                           Blocks `review_push()` until the user submits/aborts
                           or the timeout fires, then shuts down immediately.
"""

from __future__ import annotations

import enum
import json
import os
import secrets
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from genie_cli.webapp import pages
from genie_cli.webapp.layout import render_layout


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class AppMode(enum.Enum):
    INTERACTIVE = "interactive"
    REVIEW = "review"


@dataclass
class ReviewResult:
    proceed: bool = False
    justification: str = ""
    confirmation: str = ""
    reason: str = ""  # "submitted" | "aborted" | "timeout" | "closed"


# ---------------------------------------------------------------------------
# App state
# ---------------------------------------------------------------------------


@dataclass
class _AppState:
    token: str
    mode: AppMode
    cwd: str
    landing: str = "/"
    findings: list[dict[str, Any]] = field(default_factory=list)
    review_timeout: int = 300
    done: threading.Event = field(default_factory=threading.Event)
    last_heartbeat: float = field(default_factory=time.monotonic)
    review_result: ReviewResult | None = None
    # transient UI state
    saved_flags: dict[str, bool] = field(default_factory=dict)


def _user_paths() -> dict[str, Path]:
    home = Path.home()
    genie = home / ".genie"
    return {
        "home": home,
        "genie": genie,
        "hooks": genie / "hooks",
        "secret_scan": genie / "secret_scan",
        "genie_cli": genie / "genie_cli",
    }


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    server_version = "SecretGenie/2.1"
    state: _AppState  # injected via factory

    def log_message(self, *_args: Any) -> None:
        return  # silence default stderr logging

    # -- path / routing helpers -------------------------------------------------

    def _token_prefix(self) -> str:
        return f"/{self.state.token}"

    def _route(self) -> str | None:
        prefix = self._token_prefix()
        if self.path == prefix:
            return "/"
        if self.path.startswith(prefix + "/"):
            return self.path[len(prefix):] or "/"
        return None

    def _send_html(self, body_html: str, status: int = 200) -> None:
        data = body_html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, path: str) -> None:
        full = self._token_prefix() + (path if path.startswith("/") else "/" + path)
        self.send_response(302)
        self.send_header("Location", full)
        self.end_headers()

    def _page(self, body_html: str, *, title: str, active: str) -> None:
        self._send_html(
            render_layout(
                token=self.state.token,
                title=title,
                body=body_html,
                active_path=active,
                cwd=self.state.cwd,
                show_sidebar=self.state.mode == AppMode.INTERACTIVE,
            )
        )

    # -- lifecycle hooks --------------------------------------------------------

    def _bump_heartbeat(self) -> None:
        self.state.last_heartbeat = time.monotonic()

    # -- HTTP entry points ------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return

        route = self._route()
        if route is None:
            self.send_error(403, "Invalid token")
            return

        self._bump_heartbeat()

        try:
            self._dispatch_get(route)
        except Exception:
            traceback.print_exc()
            self._send_html(
                render_layout(
                    token=self.state.token, title="Error",
                    body="<h1>Something went wrong.</h1><pre>" +
                         pages.esc(traceback.format_exc()) + "</pre>",
                    active_path="/", cwd=self.state.cwd,
                    show_sidebar=self.state.mode == AppMode.INTERACTIVE,
                ),
                status=500,
            )

    def do_POST(self) -> None:  # noqa: N802
        route = self._route()
        if route is None:
            self.send_error(403, "Invalid token")
            return

        self._bump_heartbeat()

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        form = parse_qs(raw)

        try:
            self._dispatch_post(route, form)
        except Exception:
            traceback.print_exc()
            self._send_json({"ok": False, "error": "server error"}, status=500)

    # -- GET routing ------------------------------------------------------------

    def _dispatch_get(self, route: str) -> None:
        if self.state.mode == AppMode.REVIEW:
            self._get_review(route)
            return

        if route in ("/", ""):
            self._get_dashboard()
        elif route == "/install":
            self._get_install()
        elif route == "/config":
            self._get_config()
        elif route == "/exclusions":
            self._get_exclusions()
        elif route == "/scan":
            self._get_scan_idle()
        elif route == "/scan/run":
            self._get_scan_run()
        elif route == "/scan/result":
            self._get_scan_result()
        elif route == "/api/scan/status":
            self._get_scan_status()
        elif route == "/review":
            self._get_review_empty()
        else:
            self._page(
                pages.render_not_found(route),
                title="Not found", active=route,
            )

    # -- POST routing -----------------------------------------------------------

    def _dispatch_post(self, route: str, form: dict[str, list[str]]) -> None:
        if route == "/api/heartbeat":
            self._send_json({"ok": True})
            return
        if route == "/api/closed":
            self._send_json({"ok": True})
            # In review mode, tab-close == abort: we must resolve the blocking
            # caller somehow.
            if self.state.mode == AppMode.REVIEW and not self.state.done.is_set():
                self.state.review_result = ReviewResult(proceed=False, reason="closed")
                self.state.done.set()
            # In interactive mode, do NOTHING here. `beforeunload` fires on
            # every in-app navigation (not just true tab close), so using it
            # to trigger shutdown would kill the server every time the user
            # clicks a sidebar link. The plain heartbeat timeout in `launch()`
            # handles "all tabs closed" cleanly instead.
            return

        if self.state.mode == AppMode.REVIEW:
            self._post_review(route, form)
            return

        if route == "/install":
            self._post_install()
        elif route == "/uninstall":
            self._post_uninstall()
        elif route == "/config":
            self._post_config(form)
        elif route == "/exclusions":
            self._post_exclusions(form)
        else:
            self.send_error(404)

    # -- Dashboard --------------------------------------------------------------

    def _get_dashboard(self) -> None:
        data = _collect_dashboard_data()
        self._page(pages.render_dashboard(data), title="Dashboard", active="/")

    # -- Install / uninstall ----------------------------------------------------

    def _get_install(self) -> None:
        from genie_cli.hooks_installer import check_prerequisites, is_installed
        errors = check_prerequisites()
        paths = _user_paths()
        self._page(
            pages.render_install(
                installed=is_installed(),
                prerequisites_ok=not errors,
                errors=errors,
                hooks_path=str(paths["hooks"]),
                action_url="install",
            ),
            title="Install", active="/install",
        )

    def _post_install(self) -> None:
        from genie_cli.hooks_installer import install as run_install
        ok = _silent_call(run_install)
        self._page(
            pages.render_install_done(
                ok=ok,
                title="Hooks installed" if ok else "Install failed",
                detail=(
                    "SecretGenie is now watching your Git pushes on this machine."
                    if ok
                    else "See the terminal that launched SecretGenie for details."
                ),
                retry_url="install" if not ok else None,
            ),
            title="Install", active="/install",
        )

    def _post_uninstall(self) -> None:
        from genie_cli.hooks_installer import uninstall as run_uninstall
        ok = _silent_call(run_uninstall)
        self._page(
            pages.render_install_done(
                ok=ok,
                title="Hooks uninstalled" if ok else "Uninstall failed",
                detail=(
                    "Your git hooks path has been preserved so other tools keep working."
                    if ok
                    else "See the terminal that launched SecretGenie for details."
                ),
            ),
            title="Uninstall", active="/install",
        )

    # -- Config ----------------------------------------------------------------

    def _get_config(self) -> None:
        sc = _load_scan_config()
        cfg = sc.load_config()
        self._page(
            pages.render_config(
                current_mode=cfg.get("scan_mode", "both"),
                saved=self.state.saved_flags.pop("config", False),
            ),
            title="Configuration", active="/config",
        )

    def _post_config(self, form: dict[str, list[str]]) -> None:
        mode = (form.get("mode", ["both"])[0] or "both").lower()
        if mode not in {"diff", "repo", "both"}:
            mode = "both"
        sc = _load_scan_config()
        cfg = sc.load_config()
        cfg["scan_mode"] = mode
        sc.save_config(cfg)
        self.state.saved_flags["config"] = True
        self._redirect("/config")

    # -- Exclusions ------------------------------------------------------------

    def _get_exclusions(self) -> None:
        sc = _load_scan_config()
        exc = sc.load_exclusions()
        self._page(
            pages.render_exclusions(
                exclusions=exc,
                path=sc.get_exclusions_path(),
                saved=self.state.saved_flags.pop("exclusions", False),
                error=self.state.saved_flags.pop("exclusions_error", ""),  # type: ignore[arg-type]
            ),
            title="Exclusions", active="/exclusions",
        )

    def _post_exclusions(self, form: dict[str, list[str]]) -> None:
        sc = _load_scan_config()
        raw = form.get("exclusions", [""])[0]
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.state.saved_flags["exclusions_error"] = f"Invalid JSON: {exc}"  # type: ignore[assignment]
            self._redirect("/exclusions")
            return

        path = Path(sc.get_exclusions_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(parsed, indent=2))
        self.state.saved_flags["exclusions"] = True
        self._redirect("/exclusions")

    # -- Scan ------------------------------------------------------------------

    def _get_scan_idle(self) -> None:
        self._page(
            pages.render_scan_idle(),
            title="Scan", active="/scan",
        )

    def _get_scan_run(self) -> None:
        # If a scan is already in flight, reuse its progress state.
        progress = self.state.saved_flags.get("scan_progress")
        running = progress is not None and not getattr(progress, "done", True)
        if not running:
            from genie_cli.webapp.scan_runner import ScanProgress
            # Start a fresh scan, clearing any prior result.
            self.state.saved_flags.pop("scan_findings", None)
            self.state.saved_flags["scan_progress"] = ScanProgress()  # type: ignore[assignment]
            threading.Thread(target=self._do_scan, daemon=True).start()
        self._page(pages.render_scan_running(), title="Scanning", active="/scan")

    def _do_scan(self) -> None:
        from genie_cli.webapp.scan_runner import scan_repository_robust
        progress = self.state.saved_flags.get("scan_progress")
        try:
            findings = scan_repository_robust(
                cwd=Path(self.state.cwd),
                progress=progress,  # type: ignore[arg-type]
            )
            self.state.saved_flags["scan_findings"] = findings  # type: ignore[assignment]
        except Exception as exc:
            traceback.print_exc()
            if progress is not None:
                progress.error = str(exc)  # type: ignore[attr-defined]
                progress.done = True  # type: ignore[attr-defined]

    def _get_scan_result(self) -> None:
        progress = self.state.saved_flags.get("scan_progress")
        # No scan ever started — send the user to /scan/run to kick one.
        if progress is None:
            self._redirect("/scan/run")
            return

        # Still running — keep showing the progress page.
        if not getattr(progress, "done", False):
            self._page(pages.render_scan_running(), title="Scanning", active="/scan")
            return

        findings = self.state.saved_flags.get("scan_findings") or []  # type: ignore[assignment]

        # Drop the progress reference so re-entering /scan/run starts a fresh
        # scan, but keep `scan_findings` so a refresh of /scan/result still
        # shows the same result list.
        self.state.saved_flags.pop("scan_progress", None)

        self._page(
            pages.render_scan_result(
                findings=findings,  # type: ignore[arg-type]
                report_url=None,
            ),
            title="Scan result", active="/scan",
        )

    def _get_scan_status(self) -> None:
        """JSON status endpoint polled by the scan-running page."""
        progress = self.state.saved_flags.get("scan_progress")
        if progress is None:
            self._send_json({"state": "idle"})
            return
        payload = progress.to_dict()  # type: ignore[attr-defined]
        payload["state"] = "done" if payload.get("done") else "running"
        self._send_json(payload)

    # -- Review (pre-push flow) -------------------------------------------------

    def _get_review_empty(self) -> None:
        self._page(
            "<h1>No pending review</h1>"
            "<p class='lede'>This page shows up when a push is blocked by SecretGenie.</p>"
            "<div class='card'><p>Run <code>git push</code> in a repo with flagged content "
            "to see this flow.</p></div>",
            title="Review", active="/review",
        )

    def _get_review(self, route: str) -> None:
        if route in ("/", "/review", ""):
            self._page(
                pages.render_review(
                    findings=self.state.findings,
                    submit_url=f"{self._token_prefix()}/api/review/submit",
                    abort_url=f"{self._token_prefix()}/api/review/abort",
                    timeout_seconds=self.state.review_timeout,
                ),
                title="Review push", active="/review",
            )
            return
        self.send_error(404)

    def _post_review(self, route: str, form: dict[str, list[str]]) -> None:
        if route == "/api/review/submit":
            j = (form.get("justification", [""])[0] or "").strip()
            c = (form.get("confirmation", [""])[0] or "").strip()
            if len(j) < 10 or len(c) < 10:
                self._send_json({"ok": False, "error": "fields too short"}, status=400)
                return
            self.state.review_result = ReviewResult(
                proceed=True, justification=j, confirmation=c, reason="submitted"
            )
            self._send_json({"ok": True})
            self.state.done.set()
            return

        if route == "/api/review/abort":
            self.state.review_result = ReviewResult(proceed=False, reason="aborted")
            self._send_json({"ok": True})
            self.state.done.set()
            return

        self.send_error(404)



# ---------------------------------------------------------------------------
# Dashboard data collection
# ---------------------------------------------------------------------------


def _collect_dashboard_data() -> "pages.DashboardData":
    from genie_cli.hooks_installer import is_installed, _run as hook_run

    paths = _user_paths()
    sc = _load_scan_config()
    scan_mode = sc.load_config().get("scan_mode", "both")

    name = hook_run(
        ["git", "config", "--global", "user.name"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()
    email = hook_run(
        ["git", "config", "--global", "user.email"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()
    hooks_path_cfg = hook_run(
        ["git", "config", "--global", "core.hooksPath"],
        capture_output=True, check=False, text=True,
    ).stdout.strip()

    return pages.DashboardData(
        installed=is_installed(),
        hooks_path=str(paths["hooks"]),
        config_path=str(paths["secret_scan"]),
        core_hookspath=hooks_path_cfg,
        git_user=name,
        git_email=email,
        scan_mode=scan_mode,
    )


# ---------------------------------------------------------------------------
# Config / scanner helpers
# ---------------------------------------------------------------------------


def _load_scan_config():
    """Import the scan_config module from whichever location is on disk."""
    candidates = [
        Path.home() / ".genie" / "secret_scan",
        Path(__file__).resolve().parent.parent.parent / "hooks" / "scanner",
    ]
    for candidate in candidates:
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    import scan_config as sc  # type: ignore
    return sc




def _silent_call(fn) -> bool:
    """Run a function that does terminal printing without blowing up the webapp."""
    try:
        return bool(fn())
    except SystemExit as exc:
        return exc.code in (0, None)
    except Exception:
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Server launch
# ---------------------------------------------------------------------------


def _open_browser(url: str) -> bool:
    # On some Linux systems webbrowser.open blocks the main thread via xdg-open.
    # Nudge it onto a background thread so the HTTP server can start accepting.
    def _try() -> None:
        try:
            webbrowser.open_new_tab(url)
        except Exception:
            pass

    threading.Thread(target=_try, daemon=True).start()
    return True


def _make_server(state: _AppState) -> ThreadingHTTPServer:
    handler_cls = type("Handler", (_Handler,), {"state": state})
    return ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)


def launch(
    *,
    landing: str = "/",
    cwd: str | None = None,
    printer=print,
    idle_timeout: int = 60,
) -> None:
    """Start the interactive webapp, open the browser, block until the user leaves.

    The server stays up as long as SOME browser tab is sending heartbeats
    (every 15 seconds). When all tabs close, heartbeats stop and the server
    exits `idle_timeout` seconds later (60s by default). Clicking links
    inside the app does NOT trigger shutdown — only the absence of heartbeats.
    """
    state = _AppState(
        token=secrets.token_urlsafe(24),
        mode=AppMode.INTERACTIVE,
        cwd=cwd or os.getcwd(),
        landing=landing,
    )
    server = _make_server(state)
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/{state.token}{landing}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    _open_browser(url)
    printer(f"SecretGenie is running at {url}")
    printer("Close the browser tab or press Ctrl-C to stop.")

    try:
        while not state.done.wait(timeout=1.0):
            if time.monotonic() - state.last_heartbeat > idle_timeout:
                state.done.set()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def review_push(
    findings: list[dict[str, Any]],
    *,
    timeout_seconds: int = 300,
    cwd: str | None = None,
    printer=print,
) -> ReviewResult:
    """Open the review page for a pre-push scan and block for the user's decision."""
    state = _AppState(
        token=secrets.token_urlsafe(24),
        mode=AppMode.REVIEW,
        cwd=cwd or os.getcwd(),
        landing="/review",
        findings=list(findings),
        review_timeout=timeout_seconds,
    )
    server = _make_server(state)
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/{state.token}/review"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    opened = _open_browser(url)
    if opened:
        printer(f"Opened browser for review: {url}")
    else:
        printer(f"Open this URL to review: {url}")
    printer(f"Waiting up to {timeout_seconds}s for your decision...")

    deadline = time.monotonic() + timeout_seconds
    try:
        while not state.done.wait(timeout=1.0):
            if time.monotonic() > deadline:
                state.review_result = ReviewResult(proceed=False, reason="timeout")
                break
    finally:
        server.shutdown()
        server.server_close()

    return state.review_result or ReviewResult(proceed=False, reason="timeout")
