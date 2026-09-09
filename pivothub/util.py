"""通用工具：跨平台进程存活核验 / 结束（供代理链路状态核对使用）。"""

from __future__ import annotations

import os
import signal
import subprocess
import sys


def proc_alive(pid: int | None) -> bool:
    """核验本机进程是否存活（Windows 用 tasklist，POSIX 用 kill -0）。"""
    if not pid:
        return False
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=10,
            )
            return str(pid) in (out.stdout or "")
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def proc_kill(pid: int | None) -> bool:
    if not proc_alive(pid):
        return False
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False
