"""Page renderers for the SecretGenie webapp.

Each function returns an HTML body fragment which is wrapped by `layout.render_layout`
at the request handler layer.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _mask(value: str, visible: int = 3) -> str:
    if not value:
        return ""
    if len(value) <= visible * 2:
        return value
    return f"{value[:visible]}{'*' * (len(value) - visible * 2)}{value[-visible:]}"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_findings_table(findings: Iterable[dict[str, Any]]) -> str:
    rows: list[str] = []
    for idx, f in enumerate(findings, 1):
        rows.append(
            "<tr>"
            f"<td class='num'>{idx}</td>"
            f"<td class='file'>{esc(f.get('file_path', '?'))}</td>"
            f"<td class='num'>{esc(f.get('line_number', '?'))}</td>"
            f"<td><span class='tag warn'>{esc(f.get('type', 'secret'))}</span></td>"
            f"<td class='content'><code>{esc(_mask(str(f.get('line', '') or '')))}</code></td>"
            "</tr>"
        )

    if not rows:
        return "<div class='empty'><div class='big'>✓</div>No findings.</div>"

    return (
        "<table><thead><tr>"
        "<th>#</th><th>File</th><th>Line</th><th>Type</th><th>Content (masked)</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@dataclass
class DashboardData:
    installed: bool
    scan_mode: str
    git_user: str
    git_email: str


def render_dashboard(data: DashboardData) -> str:
    install_tag = (
        "<span class='tag ok'>Installed</span>"
        if data.installed
        else "<span class='tag bad'>Not installed</span>"
    )

    install_cta = (
        '<a class="btn" href="install">Reinstall hooks →</a>'
        if data.installed
        else '<a class="btn primary" href="install">Install hooks →</a>'
    )

    status_value = "Active" if data.installed else "Inactive"
    status_class = "ok" if data.installed else "bad"
    status_sub = "Watching every push" if data.installed else "Not protecting this machine yet"

    stats = f"""
    <div class="stats">
        <div class="stat">
            <div class="label">Status</div>
            <div class="value {status_class}">{status_value}</div>
            <div class="sub">{status_sub}</div>
        </div>
        <div class="stat">
            <div class="label">Scan on push</div>
            <div class="value">{esc(data.scan_mode.title())}</div>
            <div class="sub"><a href="config">Change &rarr;</a></div>
        </div>
        <div class="stat">
            <div class="label">Signed in as</div>
            <div class="value" style="font-size:15px">{esc(data.git_user) or '—'}</div>
            <div class="sub">{esc(data.git_email) or 'not set'}</div>
        </div>
    </div>
    """

    quickstart = f"""
    <div class="card">
        <div class="card-header">
            <h2>Quick actions</h2>
            {install_tag}
        </div>
        <div class="grid-2">
            <div>
                <strong>Scan this repository</strong>
                <p style="color:var(--text-muted); margin:4px 0 12px;">
                    Check every tracked file for accidentally committed secrets. Results show right here.
                </p>
                <a class="btn primary" href="scan/run">Start scan</a>
            </div>
            <div>
                <strong>Tune your settings</strong>
                <p style="color:var(--text-muted); margin:4px 0 12px;">
                    Choose what gets scanned on every push and which files to skip.
                </p>
                <a class="btn" href="config">Open settings</a>
            </div>
        </div>
        <div class="actions" style="margin-top: 20px;">
            {install_cta}
        </div>
    </div>
    """

    return f"""
    <h1>Dashboard</h1>
    <p class="lede">Local secret scanning for everything you push from this machine.</p>
    {stats}
    {quickstart}
    """


# ---------------------------------------------------------------------------
# Install wizard
# ---------------------------------------------------------------------------


def render_install(
    *,
    installed: bool,
    prerequisites_ok: bool,
    errors: list[str],
    action_url: str,
) -> str:
    status_banner = ""
    if installed:
        status_banner = (
            "<div class='banner ok'><span class='icon'>✓</span>"
            "<div><strong>SecretGenie is already enabled on this machine.</strong> "
            "Continue to refresh to the latest version.</div></div>"
        )

    if errors:
        items = "".join(f"<li>{esc(e)}</li>" for e in errors)
        status_banner += (
            f"<div class='banner error'><span class='icon'>✕</span>"
            f"<div><strong>A few things need to be set up first.</strong>"
            f"<ul style='margin:6px 0 0; padding-left:18px;'>{items}</ul></div></div>"
        )

    steps = """
    <div class="card">
        <h2>What this does</h2>
        <ul style="margin:0; padding-left:20px; color:var(--text-subtle); line-height:1.8;">
            <li>Enables automatic secret scanning every time you push.</li>
            <li>Works the same way from your terminal, VS Code, IntelliJ, GitKraken, GitHub Desktop &mdash; anywhere you push from.</li>
            <li>Runs entirely on your machine. Nothing is ever sent to a server.</li>
            <li>Plays nicely with any other security tools you already have set up.</li>
        </ul>
    </div>
    """

    proceed_label = "Refresh installation" if installed else "Enable SecretGenie"
    disabled = "" if prerequisites_ok else "disabled"

    form = f"""
    <form method="post" action="{esc(action_url)}">
        <div class="actions">
            <a class="btn subtle" href="">Cancel</a>
            <button class="btn primary large" type="submit" {disabled}>{proceed_label} →</button>
        </div>
    </form>
    """

    title = "Refresh SecretGenie" if installed else "Enable SecretGenie"
    lede = (
        "Your push will be scanned for credentials and secrets before it leaves your machine."
        if not installed
        else "Update to the latest scanner and configuration."
    )

    return f"""
    <h1>{title}</h1>
    <p class="lede">{lede}</p>
    {status_banner}
    {steps}
    {form}
    """


def render_install_done(
    *,
    ok: bool,
    title: str,
    detail: str,
    retry_url: str | None = None,
) -> str:
    cls = "ok" if ok else "bad"
    mark = "✓" if ok else "✕"
    retry = (
        f'<a class="btn" href="{esc(retry_url)}">Try again</a>'
        if retry_url and not ok
        else ""
    )
    return f"""
    <div class="done-screen {cls}">
        <div class="mark">{mark}</div>
        <h2>{esc(title)}</h2>
        <p>{esc(detail)}</p>
        <div style="display:flex; gap:8px; justify-content:center;">
            <a class="btn primary" href="">Back to dashboard</a>
            {retry}
        </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Configuration page
# ---------------------------------------------------------------------------


SCAN_MODES: list[tuple[str, str, str]] = [
    ("diff", "Changes only", "Scan only files modified since the last push. Fastest."),
    ("repo", "Full repository", "Scan every tracked file in the repo. Most thorough."),
    ("both", "Both (recommended)", "Scan both the diff and the full repository."),
]


def render_config(*, current_mode: str, saved: bool = False) -> str:
    options = []
    for value, label, desc in SCAN_MODES:
        selected = current_mode == value
        options.append(
            f"""
            <label class="radio-option {'selected' if selected else ''}">
                <input type="radio" name="mode" value="{value}" {'checked' if selected else ''}>
                <div>
                    <div class="title">{esc(label)}</div>
                    <div class="desc">{esc(desc)}</div>
                </div>
            </label>
            """
        )

    saved_banner = (
        "<div class='banner ok'><span class='icon'>✓</span><div><strong>Saved.</strong> Future pushes will use the updated setting.</div></div>"
        if saved
        else ""
    )

    return f"""
    <h1>Settings</h1>
    <p class="lede">
        Choose how SecretGenie scans your repository when you push.
        The <a href="scan">Scan</a> page always performs a full check, regardless of this setting.
    </p>
    {saved_banner}
    <form method="post" action="config">
        <div class="card">
            <h2>Scan on push</h2>
            <div class="radio-group">
                {"".join(options)}
            </div>
        </div>
        <div class="actions">
            <a class="btn subtle" href="">Cancel</a>
            <button class="btn primary" type="submit">Save settings</button>
        </div>
    </form>
    <script>
        // Highlight the selected radio option visually.
        document.querySelectorAll('.radio-option input').forEach(function (inp) {{
            inp.addEventListener('change', function () {{
                document.querySelectorAll('.radio-option').forEach(function (el) {{ el.classList.remove('selected'); }});
                inp.closest('.radio-option').classList.add('selected');
            }});
        }});
    </script>
    """


# ---------------------------------------------------------------------------
# Exclusions editor
# ---------------------------------------------------------------------------


def render_exclusions(*, exclusions: dict, saved: bool = False, error: str = "") -> str:
    pretty = json.dumps(exclusions, indent=2)
    saved_banner = (
        "<div class='banner ok'><span class='icon'>✓</span><div><strong>Saved.</strong></div></div>"
        if saved
        else ""
    )
    error_banner = (
        f"<div class='banner error'><span class='icon'>✕</span><div><strong>Could not save.</strong> {esc(error)}</div></div>"
        if error
        else ""
    )

    summary = (
        f"<strong>{len(exclusions.get('file_extensions', []))}</strong> extensions · "
        f"<strong>{len(exclusions.get('directories', []))}</strong> directories · "
        f"<strong>{len(exclusions.get('additional_exclusions', []))}</strong> additional"
    )

    return f"""
    <h1>Exclusions</h1>
    <p class="lede">
        Files and folders SecretGenie will skip during a scan. Use glob patterns
        to match anything you don't want flagged.
    </p>
    {saved_banner}
    {error_banner}
    <div class="card">
        <div class="card-header">
            <h2>Patterns</h2>
            <div class="tag">{summary}</div>
        </div>
        <form method="post" action="exclusions">
            <textarea name="exclusions" spellcheck="false" rows="22" style="min-height:420px">{esc(pretty)}</textarea>
            <div class="actions">
                <a class="btn subtle" href="">Cancel</a>
                <button class="btn primary" type="submit">Save</button>
            </div>
        </form>
    </div>
    """


# ---------------------------------------------------------------------------
# Scan page
# ---------------------------------------------------------------------------


def render_scan_idle() -> str:
    return """
    <h1>Scan this repository</h1>
    <p class="lede">Check every tracked file for accidentally committed secrets.</p>
    <div class="card">
        <h2>Ready when you are</h2>
        <p style="color:var(--text-muted); margin-top:6px;">
            A scan from here looks at every file in the repository, regardless of your push settings.
            Findings will appear on this page when the scan finishes.
        </p>
        <div class="actions left">
            <a class="btn primary large" href="scan/run">Start scan &rarr;</a>
        </div>
    </div>
    """


def render_scan_running() -> str:
    return """
    <h1>Scanning…</h1>
    <p class="lede">Reading every tracked file in the repository. You can leave this tab open.</p>

    <div class="card" id="progress-card">
        <div style="display:flex; align-items:baseline; justify-content:space-between; margin-bottom:12px;">
            <div>
                <span class="spinner" style="margin-right:8px;"></span>
                <strong id="progress-label">Starting…</strong>
            </div>
            <div style="color:var(--text-muted); font-size:13px;">
                <span id="elapsed">0s</span>
            </div>
        </div>
        <div class="progress-track"><div class="progress-fill" id="progress-fill"></div></div>
        <div class="progress-stats">
            <div><span class="stat-num" id="stat-scanned">0</span><span class="stat-label">scanned</span></div>
            <div><span class="stat-num" id="stat-total">0</span><span class="stat-label">total</span></div>
            <div><span class="stat-num" id="stat-skipped">0</span><span class="stat-label">skipped</span></div>
            <div><span class="stat-num" id="stat-findings">0</span><span class="stat-label">findings so far</span></div>
        </div>
    </div>

    <style>
        .progress-track {
            background: var(--surface-sunken);
            border: 1px solid var(--border);
            border-radius: 999px;
            height: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--ak-blue-600), var(--ak-purple-500));
            transition: width .25s ease;
        }
        .progress-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 16px;
        }
        .progress-stats > div {
            text-align: center;
            padding: 10px 8px;
            background: var(--surface-sunken);
            border-radius: var(--radius-md);
        }
        .stat-num { display: block; font-size: 20px; font-weight: 500; color: var(--text); }
        .stat-label {
            display: block; font-size: 11px; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;
        }
    </style>

    <script>
        (function () {
            var base = window.__GENIE_BASE__ || '';

            function fmtElapsed(s) {
                if (s < 60) return Math.round(s) + 's';
                var m = Math.floor(s / 60), sec = Math.round(s - m * 60);
                return m + 'm ' + sec + 's';
            }

            async function tick() {
                try {
                    var res = await fetch(base + '/api/scan/status', { cache: 'no-store' });
                    var p = await res.json();

                    if (p.state === 'done' || p.done) {
                        window.location.href = base + '/scan/result';
                        return;
                    }
                    if (p.state === 'idle') {
                        // Scan wasn't started — kick one by going to /scan/run.
                        window.location.href = base + '/scan/run';
                        return;
                    }

                    var pct = p.percent || 0;
                    document.getElementById('progress-fill').style.width = pct + '%';
                    document.getElementById('progress-label').textContent =
                        p.files_total ? ('Scanning file ' + p.files_scanned + ' of ' + p.files_total) : 'Enumerating files…';
                    document.getElementById('elapsed').textContent = fmtElapsed(p.elapsed_seconds || 0);
                    document.getElementById('stat-scanned').textContent = p.files_scanned || 0;
                    document.getElementById('stat-total').textContent = p.files_total || 0;
                    document.getElementById('stat-skipped').textContent =
                        (p.files_skipped_binary || 0) + (p.files_skipped_large || 0);
                    document.getElementById('stat-findings').textContent = p.findings_count || 0;
                } catch (e) {
                    // transient fetch failure; try again next tick
                }
                setTimeout(tick, 400);
            }
            tick();
        })();
    </script>
    <noscript>
        <meta http-equiv="refresh" content="2; url=scan/result">
        <p style="color: var(--text-muted); margin-top: 12px;">
            Page will refresh in 2 seconds. If nothing happens,
            <a href="scan/result">click here</a>.
        </p>
    </noscript>
    """


def render_scan_result(
    *,
    findings: list[dict],
    report_url: str | None = None,
) -> str:
    if not findings:
        body_cards = """
        <div class="card">
            <div class="done-screen ok">
                <div class="mark">✓</div>
                <h2>No secrets found</h2>
                <p>No secrets detected in any tracked file.</p>
            </div>
        </div>
        """
    else:
        report_link = (
            f'<a class="btn" href="{esc(report_url)}" target="_blank">Open HTML report ↗</a>'
            if report_url
            else ""
        )
        body_cards = f"""
        <div class="banner error">
            <span class="icon">⚠</span>
            <div>
                <strong>{len(findings)} potential secret(s) found.</strong>
                Review each entry below. Content is masked — only partial characters are shown.
            </div>
        </div>
        <div class="card">
            <div class="card-header">
                <h2>Findings</h2>
                {report_link}
            </div>
            {render_findings_table(findings)}
        </div>
        """

    return f"""
    <h1>Scan result</h1>
    <p class="lede">Full repository scan of every tracked file.</p>
    {body_cards}
    <div class="actions left">
        <a class="btn" href="scan/run">Rescan</a>
        <a class="btn subtle" href="">Back to dashboard</a>
    </div>
    """


# ---------------------------------------------------------------------------
# Review page (pre-push approval flow)
# ---------------------------------------------------------------------------


def render_review(
    *,
    findings: list[dict],
    submit_url: str,
    abort_url: str,
    timeout_seconds: int,
) -> str:
    findings_html = render_findings_table(findings)
    pretty_timeout = _format_duration(timeout_seconds)

    return f"""
    <h1>Review this push</h1>
    <p class="lede">
        Your push is on hold. Review each finding below, then either approve to continue
        or abort to stop the push.
    </p>
    <div class="banner warn">
        <span class="icon">⚠</span>
        <div>
            <strong>{len(findings)} potential secret(s) detected.</strong>
            This page will close automatically after <strong>{esc(pretty_timeout)}</strong> if no decision is made.
        </div>
    </div>
    <div class="card">
        <h2>Findings</h2>
        {findings_html}
    </div>
    <form id="review-form" class="card" autocomplete="off">
        <h2>Approval</h2>
        <label class="field">
            <span class="label">Why is this safe to push?</span>
       
            <textarea name="justification" rows="3" required minlength="10"
                placeholder="e.g. test fixture, not a real credential"></textarea>
        </label>
        <label class="field">
            <span class="label">Confirm there are no live secrets in this push</span>
            <textarea name="confirmation" rows="3" required minlength="10"
                placeholder="e.g. reviewed each finding, none are real credentials"></textarea>
        </label>
        <p style="color:var(--text-muted); font-size:13px; margin:4px 0 0;">
            Findings can include false positives. Your responses are saved alongside this commit
            for audit purposes.
        </p>
        <div class="actions">
            <button class="btn danger" type="button" id="abort-btn">Abort push</button>
            <button class="btn primary" type="submit">Proceed with push</button>
        </div>
        <div id="err" style="color: var(--danger); margin-top: 10px; min-height: 18px; font-size: 13px;"></div>
    </form>
    <script>
    (function () {{
        var form = document.getElementById('review-form');
        var err = document.getElementById('err');
        var abortBtn = document.getElementById('abort-btn');
        var root = document.querySelector('main');

        function renderDone(ok, title, detail) {{
            root.innerHTML =
                '<div class="done-screen ' + (ok ? 'ok' : 'bad') + '">' +
                '<div class="mark">' + (ok ? '✓' : '✕') + '</div>' +
                '<h2>' + title + '</h2>' +
                '<p>' + detail + '</p>' +
                '<p style="color:var(--text-muted); font-size:13px;">You can close this tab.</p>' +
                '</div>';
        }}

        async function post(url, body) {{
            var res = await fetch(url, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                body: new URLSearchParams(body).toString()
            }});
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        }}

        form.addEventListener('submit', async function (e) {{
            e.preventDefault();
            err.textContent = '';
            var j = form.justification.value.trim();
            var c = form.confirmation.value.trim();
            if (j.length < 10 || c.length < 10) {{
                err.textContent = 'Both fields need at least 10 characters.';
                return;
            }}
            try {{
                await post({submit_url!r}, {{ justification: j, confirmation: c }});
                renderDone(true, 'Push approved', 'Your push is continuing.');
            }} catch (ex) {{
                err.textContent = 'Could not submit: ' + ex.message;
            }}
        }});

        abortBtn.addEventListener('click', async function () {{
            try {{
                await post({abort_url!r}, {{}});
                renderDone(false, 'Push aborted', 'Remove the flagged content from your commits, then push again.');
            }} catch (ex) {{
                err.textContent = 'Could not submit: ' + ex.message;
            }}
        }});
    }})();
    </script>
    """


def _format_duration(seconds: int) -> str:
    if seconds >= 60:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


# ---------------------------------------------------------------------------
# 404 / error page
# ---------------------------------------------------------------------------


def render_not_found(path: str) -> str:
    return f"""
    <h1>Page not found</h1>
    <p class="lede">Nothing matches <code>{esc(path)}</code>.</p>
    <div class="actions left">
        <a class="btn primary" href="">Back to dashboard</a>
    </div>
    """
