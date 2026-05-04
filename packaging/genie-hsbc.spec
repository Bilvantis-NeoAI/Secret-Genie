# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for SecretGenie (HSBC variant) — identical to genie.spec
but emits a differently named binary."""

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

hidden = [
    *collect_submodules("genie_cli"),
    *collect_submodules("typer"),
    *collect_submodules("rich"),
    "dotenv",
    "yaml",
]

datas = [
    ("src/assets", "assets"),
    ("src/hooks", "hooks"),
    ("src/hooks/.env.example", "hooks/"),
    ("src/hooks/.env.sample", "hooks/"),
    ("src/genie_cli", "genie_cli"),
]

a = Analysis(
    ["src/main.py"],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["packaging/runtime_hook.py"],
    excludes=["PySide6", "PyQt5", "PyQt6", "tkinter", "textual"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="secretgenie-hsbc",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="src/assets/logo.ico",
    version="packaging/file_version_info.txt",
)
