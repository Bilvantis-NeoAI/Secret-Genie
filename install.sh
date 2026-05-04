#!/usr/bin/env bash
# SecretGenie bootstrap installer for macOS / Linux / WSL.
#
# Usage (from an end user's terminal):
#   curl -sSL https://your-host/install.sh | bash
#   # or, safer (review before running):
#   curl -sSLo install-secretgenie.sh https://your-host/install.sh
#   less install-secretgenie.sh
#   bash install-secretgenie.sh
#
# What it does:
#   1. Checks prerequisites (OS, Python 3.9+, pip, git, git identity, PATH).
#   2. Clones or updates the SecretGenie source tree under ~/.secretgenie/src.
#   3. Installs the package with `pip install --user -e .`.
#   4. Runs `secretgenie install --auto` to wire up the git pre-push hook.
#
# Fails loudly with actionable messages if any prereq is missing; does NOT
# require sudo (everything lives under $HOME).
#
# Environment overrides (mostly for testing):
#   GENIE_REPO_URL      URL to clone from.      Default: the official repo.
#   GENIE_INSTALL_DIR   Where to put the source. Default: ~/.secretgenie/src
#   GENIE_LOCAL_SOURCE  Skip clone and install from this directory instead.
#   NO_COLOR            Disable ANSI output.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — change REPO_URL once you host this publicly.
# ---------------------------------------------------------------------------
REPO_URL="${GENIE_REPO_URL:-https://github.com/Bilvantis-NeoAI/Secret-Genie.git}"
INSTALL_DIR="${GENIE_INSTALL_DIR:-$HOME/.secretgenie/src}"
MIN_PY_MAJOR=3
MIN_PY_MINOR=9

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; DIM=''; RESET=''
fi

say()  { printf "%s\n" "$*"; }
info() { printf "%s→%s %s\n"    "$BLUE"   "$RESET" "$*"; }
ok()   { printf "%s✓%s %s\n"    "$GREEN"  "$RESET" "$*"; }
warn() { printf "%s!%s %s\n"    "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf "%s✗%s %s\n"    "$RED"    "$RESET" "$*" >&2; exit 1; }

banner() {
    say ""
    say "${BOLD}${BLUE}✦ SecretGenie installer${RESET}"
    say "${DIM}Local, browser-first git hook manager for catching secrets before push.${RESET}"
    say ""
}

# ---------------------------------------------------------------------------
# Prerequisite checks — each fails with a precise remediation message.
# ---------------------------------------------------------------------------

check_os() {
    case "$(uname -s)" in
        Darwin) ok "Operating system: macOS" ;;
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                ok "Operating system: Linux (WSL)"
            else
                ok "Operating system: Linux"
            fi
            ;;
        MINGW*|CYGWIN*|MSYS*)
            die "Native Windows detected. Please use the PowerShell installer instead:
    Invoke-WebRequest -UseBasicParsing '${REPO_URL%.*}/raw/main/install.ps1' | Invoke-Expression"
            ;;
        *)
            die "Unsupported OS: $(uname -s). Supported: macOS, Linux, WSL."
            ;;
    esac
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        die "Python 3 is not installed.
   macOS:  brew install python@3.12
   Linux:  sudo apt install python3 python3-venv   (or the equivalent for your distro)
   Other:  https://www.python.org/downloads/"
    fi
    local version major minor
    version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major=${version%.*}
    minor=${version#*.}
    if [ "$major" -lt "$MIN_PY_MAJOR" ] || { [ "$major" -eq "$MIN_PY_MAJOR" ] && [ "$minor" -lt "$MIN_PY_MINOR" ]; }; then
        die "Python $version is too old — need Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR} or newer."
    fi
    ok "Python $version"
}

check_pip() {
    if ! python3 -m pip --version >/dev/null 2>&1; then
        die "pip is not available for python3.
   macOS:  python3 -m ensurepip --user
   Linux:  sudo apt install python3-pip"
    fi
    ok "pip $(python3 -m pip --version | awk '{print $2}')"
}

check_git() {
    if ! command -v git >/dev/null 2>&1; then
        die "git is not installed.
   macOS:  brew install git   (or: xcode-select --install)
   Linux:  sudo apt install git"
    fi
    ok "git $(git --version | awk '{print $3}')"
}

check_git_identity() {
    local name email
    name=$(git config --global user.name 2>/dev/null || true)
    email=$(git config --global user.email 2>/dev/null || true)
    if [ -z "$name" ] || [ -z "$email" ]; then
        die "Git identity is not configured. Please run:
    git config --global user.name \"Your Name\"
    git config --global user.email \"you@example.com\"
Then re-run this installer."
    fi
    ok "git identity: $name <$email>"
}

detect_user_bin() {
    USER_BIN="$(python3 -m site --user-base)/bin"
    if [[ ":$PATH:" == *":$USER_BIN:"* ]]; then
        PATH_ALREADY_ON=1
        ok "User bin on PATH ($USER_BIN)"
    else
        PATH_ALREADY_ON=0
    fi
}

shell_rc_file() {
    # Returns the best shell rc file for the current user, one of:
    #   ~/.zshrc, ~/.bashrc, ~/.bash_profile, ~/.config/fish/config.fish, ~/.profile
    local shell_name
    shell_name="$(basename "${SHELL:-/bin/bash}")"
    case "$shell_name" in
        zsh)
            printf "%s\n" "$HOME/.zshrc"
            ;;
        bash)
            # macOS bash traditionally sources ~/.bash_profile on login;
            # Linux bash uses ~/.bashrc for interactive shells. Prefer the
            # file the user already has; fall back by platform.
            if [ -f "$HOME/.bashrc" ]; then
                printf "%s\n" "$HOME/.bashrc"
            elif [ "$(uname)" = "Darwin" ]; then
                printf "%s\n" "$HOME/.bash_profile"
            else
                printf "%s\n" "$HOME/.bashrc"
            fi
            ;;
        fish)
            printf "%s\n" "$HOME/.config/fish/config.fish"
            ;;
        *)
            # Unknown shell — ~/.profile is sourced by most POSIX login shells.
            printf "%s\n" "$HOME/.profile"
            ;;
    esac
}

update_shell_rc() {
    if [ "$PATH_ALREADY_ON" = "1" ]; then
        # User bin is already on PATH from somewhere — nothing to do.
        return
    fi
    if [ "${GENIE_SKIP_PATH_UPDATE:-0}" = "1" ]; then
        warn "Skipping PATH update (GENIE_SKIP_PATH_UPDATE=1 set)."
        say "   Add this line yourself to your shell rc when you're ready:"
        say "       ${BOLD}export PATH=\"$USER_BIN:\$PATH\"${RESET}"
        PATH_FIX_MESSAGE="manual"
        return
    fi

    local rc_file marker_begin marker_end
    rc_file="$(shell_rc_file)"
    marker_begin="# >>> SecretGenie PATH (managed by install.sh) >>>"
    marker_end="# <<< SecretGenie PATH <<<"

    mkdir -p "$(dirname "$rc_file")"
    touch "$rc_file"

    # Idempotent: if our marker is already present, do nothing.
    if grep -qF "$marker_begin" "$rc_file"; then
        ok "PATH already configured in ${rc_file/#$HOME/~}"
        export PATH="$USER_BIN:$PATH"
        PATH_FIX_MESSAGE="applied:$rc_file"
        return
    fi

    {
        printf "\n%s\n" "$marker_begin"
        if [ "$(basename "${SHELL:-/bin/bash}")" = "fish" ]; then
            printf 'fish_add_path "%s"\n' "$USER_BIN"
        else
            printf 'export PATH="%s:$PATH"\n' "$USER_BIN"
        fi
        printf "%s\n" "$marker_end"
    } >> "$rc_file"

    # Make the new PATH effective for the rest of this install script
    # (so secretgenie install --auto can be found by short name too).
    export PATH="$USER_BIN:$PATH"
    PATH_FIX_MESSAGE="applied:$rc_file"
    ok "Added $USER_BIN to PATH in ${rc_file/#$HOME/~}"
}

# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------

fetch_source() {
    if [ -n "${GENIE_LOCAL_SOURCE:-}" ]; then
        INSTALL_DIR="$GENIE_LOCAL_SOURCE"
        info "Using local source at $INSTALL_DIR (GENIE_LOCAL_SOURCE set)"
        if [ ! -f "$INSTALL_DIR/pyproject.toml" ]; then
            die "GENIE_LOCAL_SOURCE=$INSTALL_DIR does not contain pyproject.toml"
        fi
        return
    fi

    mkdir -p "$(dirname "$INSTALL_DIR")"
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Updating existing source at $INSTALL_DIR..."
        if ! git -C "$INSTALL_DIR" pull --ff-only --quiet; then
            die "git pull failed. Fix conflicts manually, or remove $INSTALL_DIR and re-run."
        fi
        ok "Source updated"
    else
        if [ -e "$INSTALL_DIR" ]; then
            die "$INSTALL_DIR exists but is not a git repo. Remove it and re-run."
        fi
        info "Cloning $REPO_URL into $INSTALL_DIR..."
        git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR" \
            || die "git clone failed. Check network and that $REPO_URL is correct."
        ok "Source cloned"
    fi
}

install_package() {
    info "Installing SecretGenie (pip install --user -e)..."
    # Keep pip quiet unless something actually fails; let errors surface.
    if ! python3 -m pip install --user --quiet --upgrade "pip>=24.0" 2>&1 >/dev/null; then
        warn "Could not upgrade pip; continuing with the existing version."
    fi
    if ! python3 -m pip install --user --quiet --editable "$INSTALL_DIR"; then
        die "pip install failed. Run without --quiet to see the full error:
    python3 -m pip install --user --editable $INSTALL_DIR"
    fi
    ok "SecretGenie installed"
}

run_first_time_setup() {
    local genie_bin
    genie_bin="$USER_BIN/secretgenie"
    if [ ! -x "$genie_bin" ]; then
        die "secretgenie command was not created at $genie_bin. Install may be incomplete."
    fi
    info "Running first-time setup (git hook registration)..."
    # --auto = non-interactive, no browser
    if ! "$genie_bin" install --auto; then
        die "First-time setup failed. Try running manually:
    $genie_bin install"
    fi
}

final_message() {
    say ""
    say "${BOLD}${GREEN}All set!${RESET}"
    say ""
    say "Next steps:"

    case "${PATH_FIX_MESSAGE:-}" in
        applied:*)
            local rc="${PATH_FIX_MESSAGE#applied:}"
            say "  • Reload your shell to pick up the new PATH:"
            say "       ${BOLD}source ${rc/#$HOME/~}${RESET}"
            say "    (or just open a new terminal)"
            ;;
        manual)
            say "  ${YELLOW}•${RESET} Add ${BOLD}$USER_BIN${RESET} to your PATH (see instructions above)"
            ;;
        *)
            # PATH was already configured — nothing extra to do.
            ;;
    esac
    say "  • Run ${BOLD}secretgenie${RESET} to open the dashboard in your browser"
    say "  • Your next ${BOLD}git push${RESET} will be scanned automatically"
    say "  • If secrets are found, a browser tab opens for you to approve or abort"
    say ""
    say "${DIM}Source:   $INSTALL_DIR${RESET}"
    say "${DIM}Update:   cd $INSTALL_DIR && git pull && python3 -m pip install --user -e .${RESET}"
    say "${DIM}Uninstall: secretgenie uninstall --auto && rm -rf $INSTALL_DIR${RESET}"
    say ""
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    banner
    info "Checking prerequisites..."
    check_os
    check_python
    check_pip
    check_git
    check_git_identity
    detect_user_bin
    say ""
    fetch_source
    install_package
    update_shell_rc
    run_first_time_setup
    final_message
}

main "$@"
