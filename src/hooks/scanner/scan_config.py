"""Configuration helpers for SecretGenie's scanner.

Stateless utilities consumed by:
  * `src/hooks/pre_push.py`
  * `src/genie_cli/webapp/` pages + scan_runner
  * `src/genie_cli/cli.py`

There is no CLI or TUI entry point in this file — configuration UI lives
exclusively in the webapp (`secretgenie config`).
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import sys

CONFIG_FILENAME = ".genie_scan_config.json"
EXCLUSIONS_FILENAME = "exclusions.json"
GENIE_DIRNAME = ".genie"
SECRET_SCAN_SUBDIR = "secret_scan"
DEFAULT_CONFIG = {
    "scan_mode": "diff",
    "scan_changed_lines_only": True,
    "last_updated": None,
}


def _user_secret_scan_dir() -> str:
    return os.path.join(
        os.path.expanduser("~"), GENIE_DIRNAME, SECRET_SCAN_SUBDIR
    )


def get_config_path() -> str:
    return os.path.join(_user_secret_scan_dir(), CONFIG_FILENAME)


def get_exclusions_path() -> str:
    local = os.path.join(os.getcwd(), EXCLUSIONS_FILENAME)
    if os.path.exists(local):
        return local
    return os.path.join(_user_secret_scan_dir(), EXCLUSIONS_FILENAME)


def get_default_exclusions_path() -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), EXCLUSIONS_FILENAME
    )


def load_config() -> dict:
    config_path = get_config_path()
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            for key, value in DEFAULT_CONFIG.items():
                cfg.setdefault(key, value)
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> bool:
    config["last_updated"] = datetime.datetime.now().isoformat()
    config_path = get_config_path()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        ensure_exclusions_file_exists()
        return True
    except Exception:
        return False


def ensure_exclusions_file_exists() -> None:
    path = get_exclusions_path()
    if os.path.exists(path):
        return
    default = get_default_exclusions_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(default):
        shutil.copy2(default, path)
    else:
        create_default_exclusions(path)


def create_default_exclusions(path: str) -> None:
    defaults = {
        "file_extensions": [
            "*.jar", "*.war", "*.ear", "*.pyc", "*.class",
            "*.log", "*.tmp", "*.DS_Store", "*.pdf",
            "*.png", "*.jpg", "*.jpeg", "*.gif",
            "*.xlsx", "*.xls", "*.csv",
            "**/*test*.*", "**/*Test*.*",
            "*.min.js", "*.min.css",
            "*.bundle.js", "*.bundle.css",
            "*.map", "*.lock", "*.d.ts",
        ],
        "directories": [
            "**/node_modules/**", "**/dist/**", "**/build/**",
            "**/target/**", "**/.git/**",
            "**/test/**", "**/tests/**", "**/Test/**", "**/Tests/**",
            "**/*test*/**", "**/*Test*/**",
            "**/coverage/**", "**/reports/**",
            "**/.next/**", "**/.nuxt/**",
            "**/public/**", "**/static/**",
        ],
        "additional_exclusions": [],
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(defaults, f, indent=2)


_EXCLUSIONS_WARN_EMITTED = False


def _strip_jsonc_comments(text: str) -> str:
    """Best-effort removal of // line comments to tolerate JSONC-style configs."""
    import re
    return re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)


def load_exclusions() -> dict:
    global _EXCLUSIONS_WARN_EMITTED
    path = get_exclusions_path()
    if not os.path.exists(path):
        ensure_exclusions_file_exists()
    try:
        with open(path) as f:
            raw = f.read()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return json.loads(_strip_jsonc_comments(raw))
    except Exception as exc:
        if not _EXCLUSIONS_WARN_EMITTED:
            print(f"Error loading exclusions ({path}): {exc}", file=sys.stderr)
            _EXCLUSIONS_WARN_EMITTED = True
    return {"file_extensions": [], "directories": [], "additional_exclusions": []}


def get_scan_mode() -> str:
    return load_config().get("scan_mode", "both")


def should_scan_diff() -> bool:
    return get_scan_mode() in ("diff", "both")


def should_scan_repo() -> bool:
    return get_scan_mode() in ("repo", "both")


def should_scan_changed_lines_only() -> bool:
    return load_config().get("scan_changed_lines_only", True)


def should_use_exclusions() -> bool:
    return True


def get_exclusion_patterns() -> list[str]:
    excl = load_exclusions()
    return [
        *excl.get("file_extensions", []),
        *excl.get("directories", []),
        *excl.get("additional_exclusions", []),
    ]


