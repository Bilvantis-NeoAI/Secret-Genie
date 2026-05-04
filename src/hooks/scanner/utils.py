"""Utility functions for secret scanning."""

import os
import math
import logging
import subprocess
import platform
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime


def run_subprocess(cmd, **kwargs):
    """Run a subprocess command with appropriate flags to hide console window on Windows."""
    if platform.system().lower() == 'windows':
        # Add CREATE_NO_WINDOW flag on Windows to prevent console window from appearing
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    
    return subprocess.run(cmd, **kwargs)


def setup_logging(log_file: str) -> None:
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given text."""
    if not text:
        return 0
    frequency = {char: text.count(char) for char in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())

def get_git_metadata() -> Dict[str, str]:
    """Retrieve Git metadata like author, branch, commit hash, and timestamp."""
    try:
        repo_name = os.path.basename(os.getcwd())
        
        # Use run_subprocess instead of check_output
        branch_result = run_subprocess(["git", "rev-parse", "--abbrev-ref", "HEAD"], 
                                     capture_output=True, text=True, check=True)
        branch = branch_result.stdout.strip()
        
        commit_result = run_subprocess(["git", "rev-parse", "HEAD"], 
                                     capture_output=True, text=True, check=True)
        commit_hash = commit_result.stdout.strip()
        
        author_result = run_subprocess(["git", "log", "-1", "--pretty=format:%an"], 
                                     capture_output=True, text=True, check=True)
        author = author_result.stdout.strip()
        
        timestamp_result = run_subprocess(
            ["git", "log", "-1", "--pretty=format:%cd", "--date=format:%Y-%m-%d %I:%M:%S %p"],
            capture_output=True, text=True, check=True
        )
        timestamp = timestamp_result.stdout.strip()
    except subprocess.CalledProcessError:
        repo_name = "Unknown Repo"
        branch = "Unknown Branch"
        commit_hash = "Unknown Commit"
        author = "Unknown Author"
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

    return {
        "repo_name": repo_name,
        "branch": branch,
        "commit_hash": commit_hash,
        "author": author,
        "timestamp": timestamp
    }

def is_git_repo() -> bool:
    """Check if the current directory is a Git repository."""
    try:
        run_subprocess(
            ["git", "rev-parse", "--is-inside-work-tree"],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def has_unstaged_changes() -> bool:
    """Check if there are unstaged changes in Git."""
    diff_output = run_subprocess(
        ["git", "diff", "--unified=0", "--no-color"],
        capture_output=True,
        text=True
    ).stdout
    return bool(diff_output.strip())

def get_git_diff() -> Dict[str, List[Tuple[int, str]]]:
    """Retrieve the diff of changed lines from Git."""
    diff_output = run_subprocess(
        ['git', 'diff', '--unified=0', '--no-color'],
        capture_output=True,
        text=True
    ).stdout

    file_changes: Dict[str, List[Tuple[int, str]]] = {}
    current_file = None
    current_line_number = None

    for line in diff_output.splitlines():
        if line.startswith('diff --git'):
            current_file = None
        elif line.startswith('+++ b/'):
            current_file = line[6:]
            file_changes[current_file] = []
        elif line.startswith('@@'):
            import re
            match = re.search(r'\+(\d+)', line)
            if match:
                current_line_number = int(match.group(1)) - 1
        elif current_file and line.startswith('+') and not line.startswith('+++'):
            if current_line_number is not None:
                file_changes[current_file].append((current_line_number, line[1:].strip()))
                current_line_number += 1

    return file_changes

def mask_secret(secret: str, visible_chars: int = 3) -> str:
    """Mask a secret string, showing only the first and last few characters."""
    if not secret:
        return ""
    secret = str(secret)
    if len(secret) <= visible_chars * 2:
        return secret
    return f"{secret[:visible_chars]}{'*' * (len(secret) - visible_chars * 2)}{secret[-visible_chars:]}" 