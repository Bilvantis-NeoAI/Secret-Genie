"""Atlassian Design System inspired theme for the SecretGenie webapp.

All CSS is served inline (no external fonts, no CDN) so the UI works on air-gapped
machines. Light and dark palettes are both defined on `:root`; we flip between
them by toggling a `data-theme` attribute on `<html>`. The initial value respects
`prefers-color-scheme` but the user can override it via the header toggle, and we
persist the choice in localStorage.
"""

from __future__ import annotations


BASE_CSS = """
:root {
    --font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans",
                 "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "JetBrains Mono",
                 Menlo, Consolas, monospace;

    /* Atlassian-ish blue scale */
    --ak-blue-400: #4c9aff;
    --ak-blue-500: #2684ff;
    --ak-blue-600: #0065ff;
    --ak-blue-700: #0052cc;
    --ak-blue-800: #0747a6;

    --ak-red-500:    #de350b;
    --ak-red-50:     #ffebe6;
    --ak-green-500:  #00875a;
    --ak-green-50:   #e3fcef;
    --ak-yellow-500: #ff8b00;
    --ak-yellow-50:  #fffae6;
    --ak-purple-500: #6554c0;

    --radius-sm: 3px;
    --radius-md: 5px;
    --radius-lg: 8px;

    --shadow-1: 0 1px 1px rgba(9, 30, 66, 0.25), 0 0 1px rgba(9, 30, 66, 0.31);
    --shadow-2: 0 1px 3px rgba(9, 30, 66, 0.25), 0 0 1px rgba(9, 30, 66, 0.31);
    --shadow-overlay: 0 8px 12px rgba(9, 30, 66, 0.15), 0 0 1px rgba(9, 30, 66, 0.31);
}

html[data-theme="light"] {
    --bg: #ffffff;
    --canvas: #f4f5f7;
    --surface: #ffffff;
    --surface-sunken: #fafbfc;
    --surface-raised: #ffffff;
    --surface-hover: #f4f5f7;
    --surface-pressed: #ebecf0;

    --border: #dfe1e6;
    --border-strong: #c1c7d0;
    --border-input: #dfe1e6;

    --text: #172b4d;
    --text-subtle: #42526e;
    --text-muted: #6b778c;
    --text-disabled: #a5adba;
    --text-inverse: #ffffff;

    --primary: var(--ak-blue-700);
    --primary-hover: var(--ak-blue-800);
    --primary-text: #ffffff;

    --danger: var(--ak-red-500);
    --success: var(--ak-green-500);
    --warning: var(--ak-yellow-500);

    --link: var(--ak-blue-700);
}

html[data-theme="dark"] {
    --bg: #1d2125;
    --canvas: #161a1d;
    --surface: #22272b;
    --surface-sunken: #1d2125;
    --surface-raised: #282e33;
    --surface-hover: #2c333a;
    --surface-pressed: #323a42;

    --border: #393d47;
    --border-strong: #454c55;
    --border-input: #393d47;

    --text: #e6edf3;
    --text-subtle: #b6c2cf;
    --text-muted: #8993a4;
    --text-disabled: #596773;
    --text-inverse: #091e42;

    --primary: var(--ak-blue-500);
    --primary-hover: var(--ak-blue-400);
    --primary-text: #091e42;

    --danger: #ff5630;
    --success: #36b37e;
    --warning: #ffab00;

    --link: var(--ak-blue-400);

    --shadow-1: 0 1px 1px rgba(3, 4, 4, 0.6), 0 0 1px rgba(3, 4, 4, 0.6);
    --shadow-2: 0 1px 3px rgba(3, 4, 4, 0.6), 0 0 1px rgba(3, 4, 4, 0.6);
    --shadow-overlay: 0 8px 12px rgba(3, 4, 4, 0.6), 0 0 1px rgba(3, 4, 4, 0.6);
}

* { box-sizing: border-box; }
html, body { height: 100%; }
body {
    margin: 0;
    font-family: var(--font-body);
    font-size: 14px;
    line-height: 1.4286;
    color: var(--text);
    background: var(--canvas);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Top app bar */
.app-bar {
    height: 56px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    padding: 0 24px;
    gap: 16px;
    position: sticky;
    top: 0;
    z-index: 20;
}
.app-bar .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
    font-size: 15px;
    color: var(--text);
    letter-spacing: 0.01em;
}
.app-bar .brand .mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px; height: 28px;
    border-radius: var(--radius-md);
    background: linear-gradient(135deg, var(--ak-blue-700), var(--ak-purple-500));
    color: white;
    font-weight: 700;
    font-size: 14px;
}
.app-bar .spacer { flex: 1; }
.app-bar .path {
    color: var(--text-muted);
    font-size: 12.5px;
    font-family: var(--font-mono);
}

/* Shell: sidebar + main */
.shell {
    display: grid;
    grid-template-columns: 240px 1fr;
    min-height: calc(100vh - 56px);
}
.sidebar {
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
}
.sidebar .nav-section {
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 14px 12px 6px;
}
.sidebar a.nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    color: var(--text-subtle);
    border-radius: var(--radius-sm);
    font-weight: 500;
}
.sidebar a.nav-item:hover {
    background: var(--surface-hover);
    text-decoration: none;
    color: var(--text);
}
.sidebar a.nav-item.active {
    background: rgba(38, 132, 255, 0.12);
    color: var(--primary);
}
.sidebar a.nav-item .icon {
    width: 18px; height: 18px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    color: var(--text-muted);
}
.sidebar a.nav-item.active .icon { color: var(--primary); }

/* Main content */
main { padding: 32px 40px 80px; max-width: 1040px; margin: 0 auto; }
main h1 {
    font-size: 24px;
    font-weight: 500;
    margin: 0 0 4px;
    letter-spacing: -0.006em;
}
main h1 + p.lede {
    color: var(--text-muted);
    margin: 0 0 28px;
    font-size: 14px;
}
main h2 {
    font-size: 16px;
    font-weight: 600;
    margin: 32px 0 12px;
}

/* Cards */
.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 20px 22px;
    box-shadow: var(--shadow-1);
    margin-bottom: 16px;
}
.card > h2:first-child { margin-top: 0; }
.card p:last-child { margin-bottom: 0; }

.card.flat { box-shadow: none; }

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 16px;
    margin-bottom: 12px;
}
.card-header h2 { margin: 0; }

.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 720px) { .grid-2 { grid-template-columns: 1fr; } }

/* Stat tiles — auto-fit so the row stays tidy regardless of how many tiles. */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 16px 18px;
}
.stat .label {
    color: var(--text-muted);
    font-size: 11.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
}
.stat .value {
    font-size: 22px;
    font-weight: 500;
    color: var(--text);
    letter-spacing: -0.01em;
}
.stat .value.ok { color: var(--success); }
.stat .value.bad { color: var(--danger); }
.stat .sub { color: var(--text-muted); font-size: 12px; margin-top: 4px; }

/* Buttons */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 6px 14px;
    min-height: 32px;
    font: inherit;
    font-weight: 500;
    color: var(--text-subtle);
    background: var(--surface-hover);
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background .12s ease, color .12s ease, box-shadow .12s ease;
    text-decoration: none;
}
.btn:hover { background: var(--surface-pressed); color: var(--text); }
.btn:active { transform: translateY(0); }
.btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }

.btn.primary {
    background: var(--primary);
    color: var(--primary-text);
}
.btn.primary:hover { background: var(--primary-hover); color: var(--primary-text); }

.btn.danger {
    background: transparent;
    color: var(--danger);
    border-color: var(--danger);
}
.btn.danger:hover { background: var(--ak-red-50); color: var(--danger); }
html[data-theme="dark"] .btn.danger:hover { background: rgba(255,86,48,.15); }

.btn.subtle { background: transparent; }
.btn.subtle:hover { background: var(--surface-hover); }

.btn.large { min-height: 40px; padding: 8px 18px; font-size: 14px; }

.btn[disabled] { opacity: .55; cursor: not-allowed; pointer-events: none; }

.actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }
.actions.left { justify-content: flex-start; }

/* Form controls */
label.field { display: block; margin-bottom: 14px; }
label.field .label {
    display: block;
    font-weight: 500;
    font-size: 13px;
    color: var(--text-subtle);
    margin-bottom: 4px;
}
label.field .hint {
    font-weight: 400;
    color: var(--text-muted);
    margin-left: 6px;
}
input[type=text], input[type=number], textarea, select {
    width: 100%;
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border-input);
    border-radius: var(--radius-sm);
    padding: 6px 10px;
    min-height: 36px;
    font: inherit;
    transition: border-color .12s ease, box-shadow .12s ease;
}
textarea { min-height: 80px; resize: vertical; font-family: var(--font-mono); font-size: 12.5px; }
input:focus, textarea:focus, select:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--primary) 35%, transparent);
}

.radio-group { display: flex; flex-direction: column; gap: 8px; }
.radio-option {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    cursor: pointer;
    background: var(--surface);
    transition: border-color .12s ease, background .12s ease;
}
.radio-option:hover { background: var(--surface-hover); }
.radio-option input { margin-top: 3px; }
.radio-option.selected { border-color: var(--primary); background: color-mix(in srgb, var(--primary) 6%, var(--surface)); }
.radio-option .title { font-weight: 600; color: var(--text); }
.radio-option .desc { color: var(--text-muted); font-size: 13px; margin-top: 2px; }

/* Tables */
table { width: 100%; border-collapse: collapse; }
table th, table td { text-align: left; padding: 10px 12px; vertical-align: top; }
table thead th {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
}
table tbody tr { border-bottom: 1px solid var(--border); }
table tbody tr:last-child { border-bottom: none; }
table tbody tr:hover { background: var(--surface-sunken); }
table td.num { text-align: right; color: var(--text-muted); width: 56px; }
table td.file { font-family: var(--font-mono); font-size: 12.5px; color: var(--text); word-break: break-all; }
table td.content code {
    background: var(--surface-sunken);
    border: 1px solid var(--border);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    display: inline-block;
    max-width: 100%;
    overflow-wrap: anywhere;
}

/* Tags / badges */
.tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.02em;
    background: var(--surface-hover);
    color: var(--text-subtle);
}
.tag.ok { background: var(--ak-green-50); color: var(--success); }
.tag.warn { background: var(--ak-yellow-50); color: var(--ak-yellow-500); }
.tag.bad { background: var(--ak-red-50); color: var(--danger); }
html[data-theme="dark"] .tag.ok { background: rgba(54,179,126,.15); color: var(--success); }
html[data-theme="dark"] .tag.warn { background: rgba(255,171,0,.15); color: var(--warning); }
html[data-theme="dark"] .tag.bad { background: rgba(255,86,48,.15); color: var(--danger); }

.banner {
    padding: 12px 16px;
    border-radius: var(--radius-md);
    margin-bottom: 20px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    border: 1px solid;
    line-height: 1.45;
}
.banner .icon { flex-shrink: 0; font-weight: 700; }
.banner strong { font-weight: 600; }
.banner.warn  { background: var(--ak-yellow-50); color: #654a00; border-color: #ffe380; }
.banner.error { background: var(--ak-red-50); color: #7a200d; border-color: #ffbdad; }
.banner.ok    { background: var(--ak-green-50); color: #064c3a; border-color: #abf5d1; }
.banner.info  { background: #deebff; color: #0747a6; border-color: #b3d4ff; }
html[data-theme="dark"] .banner.warn  { background: rgba(255,171,0,.12); color: #f5cd47; border-color: rgba(255,171,0,.4); }
html[data-theme="dark"] .banner.error { background: rgba(255,86,48,.12); color: #ff8f73; border-color: rgba(255,86,48,.4); }
html[data-theme="dark"] .banner.ok    { background: rgba(54,179,126,.1); color: #6fddb3; border-color: rgba(54,179,126,.4); }
html[data-theme="dark"] .banner.info  { background: rgba(38,132,255,.1); color: #85b8ff; border-color: rgba(38,132,255,.4); }

.theme-toggle {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-muted);
    border-radius: var(--radius-sm);
    width: 32px; height: 32px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    font-size: 15px;
    line-height: 1;
}
.theme-toggle:hover { background: var(--surface-hover); color: var(--text); }

.kv {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 8px 20px;
    font-size: 13px;
}
.kv dt { color: var(--text-muted); }
.kv dd { margin: 0; color: var(--text); word-break: break-all; }
.kv code {
    font-family: var(--font-mono);
    font-size: 12.5px;
    background: var(--surface-sunken);
    padding: 1px 6px;
    border-radius: 3px;
}

.spinner {
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid var(--border-strong);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: spin .75s linear infinite;
    vertical-align: -2px;
}
@keyframes spin { to { transform: rotate(360deg); } }

.empty {
    text-align: center;
    color: var(--text-muted);
    padding: 40px 20px;
}
.empty .big { font-size: 36px; line-height: 1; margin-bottom: 10px; }

.section-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 16px;
    margin-top: 32px;
    margin-bottom: 12px;
}
.section-head h2 { margin: 0; }

.done-screen {
    text-align: center;
    padding: 60px 20px;
}
.done-screen .mark {
    width: 64px; height: 64px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
    line-height: 1;
    margin-bottom: 20px;
}
.done-screen.ok .mark { background: var(--ak-green-50); color: var(--success); }
.done-screen.bad .mark { background: var(--ak-red-50); color: var(--danger); }
html[data-theme="dark"] .done-screen.ok .mark { background: rgba(54,179,126,.15); }
html[data-theme="dark"] .done-screen.bad .mark { background: rgba(255,86,48,.15); }
.done-screen h2 { font-size: 20px; margin: 0 0 8px; }
.done-screen p { color: var(--text-muted); margin: 0 0 20px; }
"""


THEME_BOOT_JS = """
(function () {
    var stored = localStorage.getItem('genie-theme');
    var preferred = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', stored || preferred);
})();
"""


THEME_TOGGLE_JS = """
function toggleTheme() {
    var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('genie-theme', next);
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = next === 'dark' ? '☀' : '☾';
}
document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var t = document.documentElement.getAttribute('data-theme');
    btn.textContent = t === 'dark' ? '☀' : '☾';
});
"""


HEARTBEAT_JS = """
// Keep the ephemeral server alive while the tab is open.
(function () {
    var base = window.__GENIE_BASE__ || '';
    function ping() {
        fetch(base + '/api/heartbeat', { method: 'POST' }).catch(function () {});
    }
    setInterval(ping, 15000);
    ping();
    window.addEventListener('beforeunload', function () {
        try { navigator.sendBeacon(base + '/api/closed', ''); } catch (e) {}
    });
})();
"""
