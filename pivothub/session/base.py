"""会话基类与数据结构。所有驱动的统一契约。"""

from __future__ import annotations

import base64
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class SessionError(Exception):
    """会话层错误（网络失败/协议失败/目标不支持等）。"""


def apply_cmd_wrapper(cmd: str, wrapper: str) -> str:
    """把命令套进「提权包装器」：wrapper 里的 %CMD% 替换为 shell 安全引用的命令。

    WebShell 是无状态的一次性执行，往 /etc/passwd 里加了 root 用户也不会让会话
    本身变成 root。因此验证拿到 root 后，把后续每条命令套进
    `script -qc "su <user> -c %CMD%" /dev/null` 之类的包装器执行。
    """
    if not wrapper or "%CMD%" not in wrapper:
        return cmd
    import shlex

    return wrapper.replace("%CMD%", shlex.quote(cmd))


@dataclass
class ExecResult:
    ok: bool
    output: str = ""
    error: str = ""
    ms: int = 0
    timed_out: bool = False


@dataclass
class FileEntry:
    name: str
    is_dir: bool
    size: int = 0
    mtime: str = ""

    def to_contract(self) -> dict:
        """前端契约：{name, dir, size}（size 人类可读）。"""
        return {
            "name": self.name,
            "dir": self.is_dir,
            "size": human_size(self.size),
            "mtime": self.mtime,
        }


def human_size(n: int) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def b64e(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def parse_ls_output(text: str) -> list[FileEntry]:
    """解析 ls -la / dir /a 输出（JSP/ASPX 退化路径与反弹通道共用）。"""
    entries: list[FileEntry] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith(("total", " 文件", " Volume", " Directory")):
            continue
        # 标准 ls -la：权限 链接数 属主 属组 大小 日期 时间 名称
        m = re.match(
            r"^([d\-])[rwxstST\-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+"
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s(.+)$", line
        )
        if m:
            entries.append(FileEntry(name=m.group(4), is_dir=(m.group(1) == "d"),
                                     size=int(m.group(2)), mtime=m.group(3)))
            continue
        # 列数不固定（SELinux 上下文 / 属主属组含空格）时退化为不带大小的宽松匹配
        m_loose = re.match(
            r"^([d\-])[rwxstST\-]{9}\s+.*?\s(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s(.+)$", line
        )
        if m_loose:
            entries.append(FileEntry(name=m_loose.group(3), is_dir=(m_loose.group(1) == "d"),
                                     mtime=m_loose.group(2)))
            continue
        m2 = re.match(r"^(\d{2}/\d{2}/\d{4})\s+\d{2}:\d{2}\s+(?:<DIR>|([\d,]+))\s+(.+)$", line)
        if m2:
            size = int(m2.group(2).replace(",", "")) if m2.group(2) else 0
            entries.append(FileEntry(name=m2.group(3), is_dir=line.upper().find("<DIR>") >= 0,
                                     size=size, mtime=m2.group(1)))
    return entries


#: ls / dir 在路径不可读时的报错特征（中英文，含 Windows cmd 文案）
LS_ERR_MARKS = (
    "no such file or directory", "cannot access", "not a directory",
    "permission denied", "cannot open directory", "too many levels of symbolic links",
    "文件名、目录名或卷标语法不正确", "系统找不到指定的路径", "拒绝访问", "找不到文件",
)


def ls_error_text(text: str) -> str:
    """从 ls/dir 回显里提取错误行；没有错误返回空串。

    路径不存在 / 无权限时不能静默返回空目录，否则前端看起来像「目录是空的」。
    """
    for line in (text or "").splitlines():
        low = line.strip().lower()
        if low and any(mark in low for mark in LS_ERR_MARKS):
            return line.strip()
    return ""


class SessionBase(ABC):
    """统一会话接口：test / exec / list_dir / read_file / write_file / close。"""

    kind: str = "base"
    platform: str = "linux"  # linux | windows（由目标信息推导，供 TTY 技法选择）

    #: 是否支持在目标侧拉起 PTY（决定 tty/upgrade 的验证方式）
    supports_pty_probe: bool = False
    #: Shell.stable=True 后是否优先用 PTY 包裹执行
    prefer_pty: bool = False

    @abstractmethod
    def test(self) -> ExecResult:
        """连通性测试：返回 ok 与耗时。"""

    @abstractmethod
    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        """执行一条 shell 命令，返回真实回显。"""

    def exec_stream(self, cmd: str, on_line, timeout: float = 300.0,
                    cancel=None) -> ExecResult:
        """执行命令并逐行回调输出（默认实现：整段执行后一次性回放）。

        实时流由支持的驱动覆盖（反弹 Shell 通道边收边回调）；HTTP 马受协议限制
        只能拿到完整响应，这里保证调用方无需区分驱动。
        cancel 为 threading.Event 时支持取消（不支持的驱动忽略）。
        """
        res = self.exec(cmd, timeout=timeout)
        for line in (res.output or "").splitlines():
            on_line(line)
        return res

    @abstractmethod
    def list_dir(self, path: str) -> list[FileEntry]:
        """列目录。"""

    @abstractmethod
    def read_file(self, path: str, max_bytes: int = 512 * 1024) -> str:
        """读文件（文本），超限截断。"""

    @abstractmethod
    def write_file(self, path: str, content: str) -> None:
        """写文件（文本）。"""

    def write_file_b64(self, path: str, b64: str, append: bool = False) -> None:
        """二进制安全写入：直接落 base64 密文，由目标侧解码（默认不支持）。"""
        raise SessionError("该会话驱动不支持二进制写入")

    def upload_file(self, path: str, data: bytes, chunk_size: int = 1_200_000) -> int:
        """二进制上传（分块 append，规避 POST 体积/单参数长度限制）。返回字节数。"""
        import base64 as _b64

        if not data:
            self.write_file_b64(path, "", append=False)
            return 0
        total = 0
        first = True
        for i in range(0, len(data), chunk_size):
            self.write_file_b64(
                path, _b64.b64encode(data[i:i + chunk_size]).decode("ascii"), append=not first
            )
            first = False
            total += min(chunk_size, len(data) - i)
        return total

    def close(self) -> None:  # noqa: B027
        """释放资源（HTTP 会话无需关闭，反向通道会话在 MS3 使用）。"""

    # ---- 进程管理（Adapter 部署链路时经会话层取 pid / 清理，路由层不碰 subprocess）----

    def find_pids(self, pattern: str) -> list[int]:
        """按进程映像名（子串）查找目标侧 pid（真实执行，不伪造）。"""
        import re

        if self.platform == "windows":
            # wmic 在 Windows 11 / Server 2025 已移除 → 用 tasklist（过滤按映像名）
            cmd = f'tasklist /FI "IMAGENAME eq {pattern}" /FO CSV /NH'
        else:
            cmd = f"ps -eo pid,args | grep -- {pattern} | grep -v grep"
        res = self.exec(cmd, timeout=15)
        pids: list[int] = []
        for line in (res.output or "").splitlines():
            line = line.strip()
            if not line or "INFO:" in line or "No tasks" in line:
                continue
            if self.platform == "windows":
                m = re.match(r'^"[^"]+","(\d+)"', line)
                if m:
                    pid = int(m.group(1))
                    if pid not in pids and pid != 0:
                        pids.append(pid)
                continue
            m = re.search(r"(\d{2,7})\s*$", line)
            if m:
                pid = int(m.group(1))
                if pid not in pids and pid != 0:
                    pids.append(pid)
        return pids

    def find_pids_cmd(self, pattern: str, image: str = "") -> list[int]:
        """按命令行子串查找目标侧 pid（区分同名进程，如 chisel server/client）。

        image 非空时只认该映像名（避免把「命令行里含 client 字样」的父进程误判）。
        """
        if self.platform != "windows":
            return self.find_pids(image or pattern)
        name_filter = f"$_.Name -like '*{image}*' -and " if image else ""
        cmd = ('powershell -NoP -NonI -Command "Get-CimInstance Win32_Process '
               f"| Where-Object {{{name_filter}$_.CommandLine -like '*{pattern}*'}} "
               '| ForEach-Object {$_.ProcessId}"')
        res = self.exec(cmd, timeout=20)
        pids: list[int] = []
        for line in (res.output or "").splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
        return pids

    def pid_of_port(self, port: int) -> int | None:
        """返回监听指定端口的进程 pid（用于精确结束隧道客户端）。"""
        import re

        if not port:
            return None
        if self.platform == "windows":
            res = self.exec('powershell -NoP -NonI -Command "'
                            f'(Get-NetTCPConnection -State Listen -LocalPort {int(port)} '
                            '-ErrorAction SilentlyContinue).OwningProcess"', timeout=25)
        else:
            res = self.exec(f"(ss -lptn 2>/dev/null || netstat -lptn) | grep ':{int(port)} '",
                            timeout=20)
        text = res.output or ""
        if self.platform == "windows":
            for line in text.splitlines():
                if line.strip().isdigit():
                    return int(line.strip())
            return None
        for line in text.splitlines():
            if str(port) not in line:
                continue
            m2 = re.search(r"pid=(\d+)", line)
            if m2:
                return int(m2.group(1))
        return None

    def kill_pid(self, pid: int) -> bool:
        """结束目标侧进程（真实执行）。"""
        if self.platform == "windows":
            res = self.exec(f"taskkill /F /PID {int(pid)}", timeout=12)
        else:
            res = self.exec(f"kill -9 {int(pid)} 2>/dev/null; echo done", timeout=12)
        return bool(res.ok)

    def pty_probe(self, inner_cmd: str, timeout: float = 15.0) -> ExecResult:
        """在目标侧 PTY 内执行 inner_cmd 并返回真实回显（PTY 判定的依据）。

        默认不支持：抛 SessionError，由调用方降级处理。
        """
        raise SessionError("该会话驱动不支持 PTY 探测")
