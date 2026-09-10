"""会话抽象层：一切命令执行 / 文件读写的唯一出口。

硬约束（任务书 3）：任何命令执行/文件读写都不得把 subprocess/os.system 写进
路由函数，统一走 Session 接口（为后续冰蝎/哥斯拉协议留扩展点）。
"""

from .base import ExecResult, FileEntry, SessionBase, SessionError
from .registry import get_session
from .http_shell import HttpShellSession
from .local import LocalSession
from .ssh import SshSession, parse_ssh_url
from .reverse import (
    SERVICE as REVERSE_SERVICE,
    ReverseShellChannel,
    ReverseShellListener,
    ReverseShellService,
)

__all__ = [
    "ExecResult", "FileEntry", "SessionBase", "SessionError",
    "get_session", "HttpShellSession", "LocalSession", "SshSession", "parse_ssh_url",
    "REVERSE_SERVICE", "ReverseShellChannel", "ReverseShellListener", "ReverseShellService",
]
