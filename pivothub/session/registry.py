"""会话注册表：Shell 记录 → 会话实例。路由层唯一入口。"""

from __future__ import annotations

from ..models import Host, Shell
from .base import SessionBase, SessionError
from .http_shell import HttpShellSession, WINDOWS, lang_of
from .local import LocalSession


def get_session(shell: Shell, host: Host | None = None,
                platform: str | None = None) -> SessionBase:
    """根据 Shell 记录构造对应驱动。

    kind='ssh'（或 type 含 "ssh"）：走 SSH 协议纳管（A7）。
    其余维持既有：PHP/JSP/ASP/ASPX 一句话马（HTTP 协议）+ 通用命令回显端点。

    platform 显式给出时优先（自动档部署需要按目标真实平台选择二进制/命令）。
    """
    # A7：SSH 会话优先按 kind 路由（type 含 "ssh" 也容错识别，如 "SSH 会话"）
    if getattr(shell, "kind", "") == "ssh" or "ssh" in (shell.type or "").lower():
        from .ssh import SshSession, parse_ssh_url

        user, ssh_host, port = parse_ssh_url(shell.url)
        platform_ = platform
        if not platform_:
            if getattr(shell, "platform", ""):
                platform_ = shell.platform
            elif host and host.os and "windows" in host.os.lower():
                platform_ = "windows"
            else:
                platform_ = "linux"
        return SshSession(
            host=ssh_host, port=port, username=user, password=shell.pwd,
            platform=platform_,
        )

    lang = lang_of(shell.type, shell.url)
    if lang == "unknown":
        raise SessionError(
            f"暂不支持的会话类型: {shell.type}（冰蝎/哥斯拉协议属二期范围）"
        )
    if not platform:
        platform = "windows" if (host and host.os and "windows" in host.os.lower()) else "linux"
        if "asp" in (shell.type or "").lower():
            platform = "windows"
    return HttpShellSession(
        url=shell.url, pwd=shell.pwd, encoder=shell.encoder,
        shell_type=shell.type, platform=platform,
    )
