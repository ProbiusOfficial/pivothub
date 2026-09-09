"""本机会话驱动：供联调靶标（miniweb 所在主机）/ 本地管理操作使用。

注意：仅会话层内部允许 subprocess；api/ 路由层禁止。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime

from .base import ExecResult, FileEntry, SessionBase, SessionError


class LocalSession(SessionBase):
    kind = "local"

    def __init__(self, platform: str | None = None) -> None:
        self.platform = platform or ("windows" if sys.platform == "win32" else "linux")
        self.prefer_pty = False

    def test(self) -> ExecResult:
        start = time.perf_counter()
        res = self.exec("echo ok")
        return ExecResult(ok=res.ok, output=res.output, ms=int((time.perf_counter() - start) * 1000))

    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, timeout=timeout,
                text=True, errors="replace",
            )
        except subprocess.TimeoutExpired:
            return ExecResult(ok=False, timed_out=True, error=f"命令超时（>{timeout}s）")
        except Exception as e:
            return ExecResult(ok=False, error=str(e))
        out = (proc.stdout or "") + (proc.stderr or "")
        return ExecResult(ok=proc.returncode == 0, output=out.rstrip("\r\n"), ms=int((time.perf_counter() - start) * 1000))

    def list_dir(self, path: str) -> list[FileEntry]:
        try:
            names = os.listdir(path)
        except OSError as e:
            raise SessionError(f"列目录失败: {e}") from e
        entries = []
        for name in names:
            if name == ".":
                continue
            full = os.path.join(path, name)
            try:
                st = os.stat(full)
                entries.append(FileEntry(
                    name=name, is_dir=os.path.isdir(full),
                    size=st.st_size if not os.path.isdir(full) else 0,
                    mtime=datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                ))
            except OSError:
                entries.append(FileEntry(name=name, is_dir=False, size=0))
        return entries

    def read_file(self, path: str, max_bytes: int = 512 * 1024) -> str:
        try:
            with open(path, "rb") as f:
                return f.read(max_bytes).decode("utf-8", "replace")
        except OSError as e:
            raise SessionError(f"读取失败: {e}") from e

    def write_file(self, path: str, content: str) -> None:
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
        except OSError as e:
            raise SessionError(f"写入失败: {e}") from e

    def write_file_b64(self, path: str, b64: str, append: bool = False) -> None:
        import base64

        try:
            with open(path, "ab" if append else "wb") as f:
                f.write(base64.b64decode(b64))
        except OSError as e:
            raise SessionError(f"写入失败: {e}") from e
