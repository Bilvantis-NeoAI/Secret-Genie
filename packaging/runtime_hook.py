"""Runtime hook for the PyInstaller-frozen SecretGenie binary.

Ensures that the bundled `src/` tree is importable so `genie_cli`,
`secretscan`, and friends resolve when running from the frozen app.
"""

import os
import sys


def _add_meipass_paths() -> None:
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return
    for relative in ("", "hooks", os.path.join("hooks", "scanner")):
        path = os.path.join(meipass, relative) if relative else meipass
        if os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)


_add_meipass_paths()
