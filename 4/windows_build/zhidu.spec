# -*- mode: python ; coding: utf-8 -*-
# 智读 · PyInstaller 规格文件
# 构建: pyinstaller zhidu.spec

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve()

a = Analysis(
    ['zhidu_app.py'],
    pathex=[str(ROOT / 'backend'), str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / 'frontend'), 'frontend'),
    ],
    hiddenimports=['pypdf', 'fontTools'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PIL'],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='智读',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # 保留控制台以便查看地址与日志；改 False 可隐藏窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
