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
    hooks_path: str
    config_path: str
    core_hookspath: str
    git_user: str
    git_email: str
    scan_mode: str


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

    stats = f"""
    <div class="stats">
        <div class="stat">
            <div class="label">Hooks</div>
            <div class="value {'ok' if data.installed else 'bad'}">{('Active' if data.installed else 'Inactive')}</div>
            <div class="sub">{esc(data.hooks_path)}</div>
        </div>
        <div class="stat">
            <div class="label">Pre-push scan mode</div>
            <div class="value">{esc(data.scan_mode.title())}</div>
            <div class="sub"><a href="config">Configure →</a></div>
        </div>
        <div class="stat">
            <div class="label">Git identity</div>
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
                    Run a full secret scan on the current repository and view the findings here.
                </p>
                <a class="btn primary" href="scan/run">Start scan</a>
            </div>
            <div>
                <strong>Configure scanning</strong>
                <p style="color:var(--text-muted); margin:4px 0 12px;">
                    Change scan mode, edit exclusion patterns, review what gets skipped.
                </p>
                <a class="btn" href="config">Open settings</a>
            </div>
        </div>
    </div>
    """

    details = f"""
    <div class="card">
        <h2>Installation details</h2>
        <dl class="kv">
            <dt>Install status</dt><dd>{install_tag}</dd>
            <dt>Hooks directory</dt><dd><code>{esc(data.hooks_path)}</code></dd>
            <dt>Scanner directory</dt><dd><code>{esc(data.config_path)}</code></dd>
            <dt>Git core.hooksPath</dt><dd><code>{esc(data.core_hookspath) or '(unset)'}</code></dd>
            <dt>Git user.name</dt><dd>{esc(data.git_user) or "<span class='tag bad'>unset</span>"}</dd>
            <dt>Git user.email</dt><dd>{esc(data.git_email) or "<span class='tag bad'>unset</span>"}</dd>
        </dl>
        <div class="actions">
            {install_cta}
        </div>
    </div>
    """

    return f"""
    <h1>Dashboard</h1>
    <p class="lede">Everything SecretGenie is doing on this machine.</p>
    {stats}
    {quickstart}
    {details}
    """


# ---------------------------------------------------------------------------
# Install wizard
# ---------------------------------------------------------------------------


def render_install(
    *,
    installed: bool,
    prerequisites_ok: bool,
    errors: list[str],
    hooks_path: str,
    action_url: str,
) -> str:
    status_banner = ""
    if installed:
        status_banner = (
            "<div class='banner ok'><span class='icon'>✓</span>"
            "<div><strong>Already installed.</strong> Re-running installation will "
            "refresh the hook files to the current version.</div></div>"
        )

    if errors:
        items = "".join(f"<li>{esc(e)}</li>" for e in errors)
        status_banner += (
            f"<div class='banner error'><span class='icon'>✕</span>"
            f"<div><strong>Prerequisites not met.</strong><ul style='margin:6px 0 0; padding-left:18px;'>{items}</ul></div></div>"
        )

    steps = f"""
    <div class="card">
        <h2>What will happen</h2>
        <ol style="margin:0; padding-left:20px; color:var(--text-subtle); line-height:1.8;">
            <li>Copy hook scripts into <code>{esc(hooks_path)}</code>.</li>
            <li>Set <code>git config --global core.hooksPath</code> to that directory.</li>
            <li>Register git aliases so <code>git scan-config</code> and <code>git secret-scan</code> work.</li>
            <li>Existing hooks configured by other tools are preserved on uninstall.</li>
        </ol>
    </div>
    """

    proceed_label = "Reinstall hooks" if installed else "Install hooks"
    disabled = "" if prerequisites_ok else "disabled"

    form = f"""
    <form method="post" action="{esc(action_url)}">
        <div class="actions">
            <a class="btn subtle" href="">Cancel</a>
            <button class="btn primary large" type="submit" {disabled}>{proceed_label} →</button>
        </div>
    </form>
    """

    return f"""
    <h1>{"Reinstall" if installed else "Install"} hooks</h1>
    <p class="lede">SecretGenie installs a pre-push hook globally via <code>core.hooksPath</code>.</p>
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
    <h1>Configuration</h1>
    <p class="lede">
        Controls how the <strong>pre-push hook</strong> scans your repository
        when you run <code>git push</code>. Manual scans started from the
        <a href="scan">Scan</a> page always run a full repository scan and
        ignore this setting.
    </p>
    {saved_banner}
    <form method="post" action="config">
        <div class="card">
            <h2>Pre-push scan mode</h2>
            <div class="radio-group">
                {"".join(options)}
            </div>
        </div>
        <div class="actions">
            <a class="btn subtle" href="">Cancel</a>
            <button class="btn primary" type="submit">Save configuration</button>
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


def render_exclusions(*, exclusions: dict, path: str, saved: bool = False, error: str = "") -> str:
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
        Glob patterns that tell SecretGenie to skip files or directories.
        Stored at <code>{esc(path)}</code>.
    </p>
    {saved_banner}
    {error_banner}
    <div class="card">
        <div class="card-header">
            <h2>Pattern list</h2>
            <div class="tag">{summary}</div>
        </div>
        <form method="post" action="exclusions">
            <textarea name="exclusions" spellcheck="false" rows="22" style="min-height:420px">{esc(pretty)}</textarea>
            <div class="actions">
                <a class="btn subtle" href="">Cancel</a>
                <button class="btn primary" type="submit">Save exclusions</button>
            </div>
        </form>
    </div>
    """


# ---------------------------------------------------------------------------
# Scan page
# ---------------------------------------------------------------------------


def render_scan_idle() -> str:
    return """
    <h1>Scan repository</h1>
    <p class="lede">Run a one-shot full scan of the current repository.</p>
    <div class="card">
        <h2>Ready to scan</h2>
        <p style="color:var(--text-muted); margin-top:6px;">
            Every scan from here checks every tracked file in the repository.
            The scan-mode setting on the <a href="config">Configuration</a> page
            applies to automated pre-push scans only.
        </p>
        <div class="actions left">
            <a class="btn primary large" href="scan/run">Start scan →</a>
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
    <h1>Approve this push</h1>
    <p class="lede">
        Your Git client doesn't have a terminal to show an interactive prompt, so we opened
        this page instead. Review the findings below, then approve or abort.
    </p>
    <div class="banner warn">
        <span class="icon">⚠</span>
        <div>
            <strong>{len(findings)} potential secret(s) detected.</strong>
            Waiting up to <strong>{esc(pretty_timeout)}</strong> for your decision.
        </div>
    </div>
    <div class="card">
        <h2>Findings</h2>
        {findings_html}
    </div>
    <form id="review-form" class="card" autocomplete="off">
        <h2>Approval</h2>
        <label class="field">
            <span class="label">Justification <span class="hint">(min 10 chars — why this is acceptable)</span></span>
            <textarea name="justification" rows="3" required minlength="10"
                placeholder="e.g. test fixture, not a real credential"></textarea>
        </label>
        <label class="field">
            <span class="label">Confirmation <span class="hint">(min 10 chars — confirm no live secrets are committed)</span></span>
            <textarea name="confirmation" rows="3" required minlength="10"
                placeholder="e.g. reviewed each finding, none are real credentials"></textarea>
        </label>
        <p style="color:var(--text-muted); font-size:13px; margin:4px 0 0;">
            SecretGenie uses regex and entropy heuristics. Results may contain false positives or
            miss real secrets — your responses are recorded in the commit message.
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
                renderDone(true, 'Push approved', 'Returning to your Git client…');
            }} catch (ex) {{
                err.textContent = 'Could not submit: ' + ex.message;
            }}
        }});

        abortBtn.addEventListener('click', async function () {{
            try {{
                await post({abort_url!r}, {{}});
                renderDone(false, 'Push aborted', 'Remove the findings from your commit, then push again.');
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
