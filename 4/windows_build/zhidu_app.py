#!/usr/bin/env python3
"""智读正式版 · 打包入口（PyInstaller 用）"""
import sys
from pathlib import Path

# 确保 backend 在路径中（源码运行时）
_ROOT = Path(__file__).resolve().parent
_BACKEND = _ROOT / "backend"
if _BACKEND.is_dir() and str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from server import main

if __name__ == "__main__":
    main()
