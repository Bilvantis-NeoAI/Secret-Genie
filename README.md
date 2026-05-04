# SecretGenie

SecretGenie is a **local, browser-first** Git hook manager that catches
accidentally committed secrets — API keys, tokens, private keys, credentials
— before they leave your machine. Every interaction (install, configure,
scan, approve a push) happens in an Atlassian-flavoured local web app with
both dark and light modes. Pure regex + Shannon entropy, no cloud calls.

## Quick start

The installer is the same shape everywhere: check prereqs → clone source to your home directory → `pip install --user -e .` → register the git pre-push hook → add the user-bin directory to PATH. **No sudo, no admin**, nothing written outside your home / user profile.

> **Prerequisites on every platform**
> - Python **3.9+**
> - `pip` (bundled with Python on most installs)
> - `git` with `user.name` and `user.email` configured globally
>
> The installer verifies all of these before touching anything and prints an exact fix for whatever is missing.

### macOS

```bash
# 1. Prereqs (skip the ones you already have)
brew install python@3.12 git
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# 2. Install SecretGenie
curl -sSL https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh | bash

# 3. Reload your shell so the new PATH entry is picked up
source ~/.zshrc         # zsh (default on macOS 10.15+)
# or: source ~/.bash_profile    # if you use bash

# 4. Verify
secretgenie --version   # → ✦ SecretGenie v2.0.0
secretgenie             # opens the dashboard in your browser
```

### Linux (Debian / Ubuntu / WSL)

```bash
# 1. Prereqs
sudo apt update
sudo apt install -y python3 python3-pip git
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# 2. Install SecretGenie
curl -sSL https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh | bash

# 3. Reload your shell
source ~/.bashrc        # bash (most common on Linux)
# or: source ~/.zshrc           # if you use zsh

# 4. Verify
secretgenie --version
secretgenie
```

### Linux (Fedora / RHEL / CentOS)

```bash
# 1. Prereqs
sudo dnf install -y python3 python3-pip git
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# 2–4. Same as Debian/Ubuntu above
curl -sSL https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh | bash
source ~/.bashrc
secretgenie --version
```

### Windows (PowerShell 5+)

```powershell
# 1. Prereqs (skip if already installed)
winget install --id Python.Python.3.12 -e
winget install --id Git.Git -e
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# 2. Install SecretGenie
iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.ps1').Content

# 3. Open a NEW PowerShell window so the updated PATH is picked up
#    (PowerShell doesn't re-read environment in the current session.)

# 4. Verify (in the new window)
secretgenie --version   # → ✦ SecretGenie v2.0.0
secretgenie             # opens the dashboard in your browser
```

If you'd rather not use `winget`, download Python 3.9+ from [python.org](https://www.python.org/downloads/windows/) (tick **Add python.exe to PATH** during install) and Git from [git-scm.com](https://git-scm.com/download/win).

### Review before running (all platforms)

If piping `curl | bash` / `iex` makes you uncomfortable (fair), download and read first:

```bash
# macOS / Linux / WSL
curl -sSLo install-secretgenie.sh https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.sh
less install-secretgenie.sh
bash install-secretgenie.sh
```

```powershell
# Windows
iwr -UseBasicParsing 'https://raw.githubusercontent.com/Bilvantis-NeoAI/Secret-Genie/main/install.ps1' -OutFile install-secretgenie.ps1
notepad install-secretgenie.ps1
powershell -ExecutionPolicy Bypass -File install-secretgenie.ps1
```

### Manual install (from source)

```bash
# macOS / Linux / WSL
git clone https://github.com/Bilvantis-NeoAI/Secret-Genie.git
cd Secret-Genie
python3 -m pip install --user -e .
secretgenie install               # opens the install wizard
```

```powershell
# Windows
git clone https://github.com/Bilvantis-NeoAI/Secret-Genie.git
cd Secret-Genie
python -m pip install --user -e .
secretgenie install
```

### Shipping a pre-built binary

If your users can't run Python directly:

```bash
./build.sh                    # macOS / Linux  → dist/secretgenie
```
```batch
build.bat                     :: Windows       → dist\secretgenie.exe
```

Drop the resulting binary on PATH and run `secretgenie install`.

### Updating

```bash
# macOS / Linux / WSL
cd ~/.secretgenie/src
git pull
python3 -m pip install --user -e .
```

```powershell
# Windows
cd $env:USERPROFILE\.secretgenie\src
git pull
python -m pip install --user -e .
```

Or just re-run the one-line installer — it's fully idempotent.

### Uninstalling

```bash
# macOS / Linux / WSL
secretgenie uninstall --auto
python3 -m pip uninstall -y secretgenie
rm -rf ~/.secretgenie
# (Optional) open ~/.zshrc (or ~/.bashrc) and delete the marked block:
#   # >>> SecretGenie PATH (managed by install.sh) >>>
#   export PATH="..."
#   # <<< SecretGenie PATH <<<
```

```powershell
# Windows
secretgenie uninstall --auto
python -m pip uninstall -y secretgenie
Remove-Item -Recurse -Force $env:USERPROFILE\.secretgenie
# (Optional) remove the user-bin entry from your user PATH in
# Settings → Environment Variables → User
```

`secretgenie uninstall --auto` removes the git hooks and `~/.genie/` but intentionally leaves `core.hooksPath` set, so any other security tools using it keep working.

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
