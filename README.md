# SecretGenie

SecretGenie is a **local, browser-first** Git hook manager that catches
accidentally committed secrets — API keys, tokens, private keys, credentials
— before they leave your machine. Every interaction (install, configure,
scan, approve a push) happens in an Atlassian-flavoured local web app with
both dark and light modes. Pure regex + Shannon entropy, no cloud calls.

## Quick start

### One-line install (macOS / Linux / WSL)

```bash
curl -sSL https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh | bash
```

Prefer to review before running:

```bash
curl -sSLo install-secretgenie.sh https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh
less install-secretgenie.sh
bash install-secretgenie.sh
```

### One-line install (Windows PowerShell)

```powershell
iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.ps1').Content
```

Either script:

1. Verifies prerequisites (Python 3.9+, pip, git, git identity, writable user-bin on PATH).
2. Clones the source tree to `~/.secretgenie/src` (or `%USERPROFILE%\.secretgenie\src`).
3. Runs `pip install --user -e .` so the `secretgenie` command is on your PATH.
4. Runs `secretgenie install --auto` to register the git pre-push hook.

If anything is missing, the installer fails loudly with an exact remediation message. Nothing is installed outside your home directory; no `sudo`.

### Manual install (from source)

```bash
git clone https://github.com/Bilvantis-NeoAI/Secret-Genie.git
cd Secret-Genie
python -m pip install --user -e .
secretgenie install               # opens the install wizard in your browser
```

### Shipping a pre-built binary

Run `./build.sh` (macOS/Linux) or `build.bat` (Windows). The output is `dist/secretgenie[.exe]`. Drop it on your PATH and use `secretgenie install`.

## How it works

Every command spins up a **short-lived HTTP server on `127.0.0.1`**, opens
your default browser to the right landing page, and exits when you close the
tab. Nothing runs in the background between commands, no daemon, no Docker.

```bash
secretgenie              # dashboard (install status, scan mode, quick actions)
secretgenie install      # install wizard
secretgenie uninstall    # shown on the install page
secretgenie scan         # run a scan and view results in the browser
secretgenie config       # choose scan mode / edit exclusions
```

### Automation

Three `--auto` / `--json` escape hatches bypass the browser so you can use
SecretGenie from CI, Dockerfiles, or SSH on headless servers:

```bash
secretgenie install --auto        # silent install
secretgenie uninstall --auto      # silent uninstall
secretgenie scan --json           # emit findings JSON to stdout
```

Exit codes for `--json`: `0` = clean, `1` = findings, `2` = error.

## Pre-push flow

After install, every `git push` — from a terminal, from VS Code, from
IntelliJ, from GitKraken, from GitHub Desktop — runs the pre-push hook:

1. Collect files being pushed and scan them.
2. If nothing is flagged → push proceeds silently.
3. If secrets are flagged → the hook **opens a browser tab** at the
   SecretGenie review page. You see a masked findings table, fill in a
   justification + confirmation, and click **Proceed** or **Abort**. The
   hook reads the decision, appends the justification to your commit
   message, writes a local HTML report, and either lets the push through
   or blocks it.

The review page binds to `127.0.0.1` only, uses a per-session token in the
URL, and shuts down as soon as a decision is made (or after a 5-minute
timeout).

### Truly headless environments

If no browser is available (CI runner, minimal Docker image, SSH with no
`$BROWSER`), the hook prints the review URL to stderr and keeps waiting so
you can port-forward it and open it locally. If the timeout elapses
without a decision, the push is aborted.

## UI

The web app uses Atlassian-style design tokens (`#0052cc` primary, Noto
Sans / system font stack, 3px radius, subtle shadows). Light and dark
themes are both available — the app respects `prefers-color-scheme` on
first load and remembers your manual choice in `localStorage`.

Pages:
- **Dashboard** — install status, git identity, scan mode, quick actions.
- **Scan** — run a scan on the current repo, see findings with masked content.
- **Configuration** — scan mode picker (diff / repo / both).
- **Exclusions** — JSON editor for exclusion patterns.
- **Install** — install / reinstall wizard with prerequisite checks.
- **Review** — shown only during a pre-push hook when secrets are detected.

## What SecretGenie installs

On `install`, these are written to your home directory:

```
~/.genie/
├── hooks/           # pre-push + helper shell scripts (global core.hooksPath)
├── secret_scan/     # scanner code, config, and exclusions
└── genie_cli/       # the CLI + webapp package (so the hook can open the browser)
```

`git config --global core.hooksPath` is set to `~/.genie/hooks/`. Uninstall
preserves this setting for compatibility with other security tools.

## License

MIT.
