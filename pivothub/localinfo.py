"""面板所在机器（攻击机）的真实信息：主机名 / 操作系统 / 网卡 / 当前用户。

拓扑根「攻击端本机」与攻击机网卡都取这里的值：启动时按运行环境校正一次，
新建项目与首次播种也用它，避免换机后仍显示上一台机器的系统与网卡。
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
import sys
from pathlib import Path


def hostname() -> str:
    """面板所在机器的主机名。"""
    try:
        return socket.gethostname() or "localhost"
    except OSError:  # pragma: no cover - 极少数受限环境
        return "localhost"


def os_name() -> str:
    """人类可读的系统名，如 Windows 11 (10.0.26200) / Debian 12 / macOS 15.2。"""
    if sys.platform == "win32":
        ver = platform.version()
        try:
            build = int(ver.rsplit(".", 1)[-1])
        except ValueError:
            build = 0
        try:
            edition = platform.win32_edition() or ""
        except (AttributeError, ValueError):  # pragma: no cover - 旧解释器
            edition = ""
        if "Server" in edition:
            return f"Windows Server ({ver})"
        rel = platform.release()
        if rel == "10" and build >= 22000:  # 老版本 Python 把 Win11 报成 10
            rel = "11"
        return f"Windows {rel} ({ver})"
    if sys.platform == "darwin":
        mac = platform.mac_ver()[0]
        return f"macOS {mac}" if mac else "macOS"
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return platform.platform()
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.platform()


def privilege() -> str:
    """当前运行用户的权限标识（root / Administrator / 用户名）。"""
    if sys.platform == "win32":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
                return "Administrator"
        except Exception:
            pass
        return getpass.getuser()
    try:
        if os.geteuid() == 0:
            return "root"
    except AttributeError:  # pragma: no cover - Windows 已在上面返回
        pass
    return getpass.getuser()


def iface_for(ip: str) -> str:
    """本机持有该地址的网卡名；psutil 缺失或地址不属于本机时返回空串。"""
    if not ip:
        return ""
    try:
        import psutil
    except ImportError:
        return ""
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip:
                    return name
    except Exception:
        return ""
    return ""


def interface_names() -> list[str]:
    """本机全部网卡名（用于判断库中存的网卡名是否仍存在于本机）。"""
    try:
        import psutil
    except ImportError:
        return []
    try:
        return list(psutil.net_if_addrs().keys())
    except Exception:
        return []


def machine() -> dict:
    """本机信息快照：{hostname, os, privilege}。"""
    return {"hostname": hostname(), "os": os_name(), "privilege": privilege()}


def _local_note(iface: str, ip: str) -> str:
    iface = iface or "iface"
    return f"攻击端本机（{iface} · {ip}）· 面板运行位置"


def sync_local_machine(db) -> list[str]:
    """把各项目的本机节点与攻击机网卡校正为当前真实机器信息。

    - 主机名 / 操作系统 / 权限：始终跟随面板所在机器；
    - 网卡名：库中存的网卡在本机已不存在时，按攻击机 IP 反查真实网卡名；
    - 备注：仅重写自动生成的「攻击端本机…」备注，不动用户手写内容。

    返回发生变更的项目 id 列表；调用方负责 commit。
    """
    from .db import get_attack, set_attack
    from .models import Host, Project

    name, osname, priv = hostname(), os_name(), privilege()
    ifaces = set(interface_names())
    changed: list[str] = []

    for host in db.query(Host).filter(Host.is_local.is_(True)).all():
        dirty = False
        if host.hostname != name:
            host.hostname = name
            dirty = True
        if host.os != osname:
            host.os = osname
            dirty = True
        if host.privilege != priv:
            host.privilege = priv
            dirty = True

        rows = [dict(x or {}) for x in (host.ifaces or [])]
        real_iface = iface_for(host.ip)
        if rows:
            cur = rows[0].get("iface") or ""
            if real_iface and cur not in ifaces and cur != real_iface:
                rows[0]["iface"] = real_iface
                dirty = True
        elif real_iface:
            rows = [{"iface": real_iface, "ip": host.ip, "segment": host.segment}]
            dirty = True
        if dirty:
            host.ifaces = rows
        first_iface = (rows[0].get("iface") if rows else "") or ""

        if not host.note or host.note.startswith("攻击端本机"):
            note = _local_note(first_iface, host.ip)
            if host.note != note:
                host.note = note
                dirty = True

        if dirty:
            changed.append(host.project_id)

    # 攻击机配置里的网卡名同样自愈（换机后 eth0/tun0 可能并不存在）
    for project in db.query(Project).all():
        try:
            attack = get_attack(db, project.id)
        except Exception:  # pragma: no cover - 配置损坏时跳过
            continue
        cur = attack.get("iface") or ""
        real = iface_for(attack.get("ip") or "")
        if real and cur and cur not in ifaces and cur != real:
            # set_attack 以默认值为底再合并，必须传整份配置，否则会丢项目自定义 IP/网段
            set_attack(db, project.id, {**attack, "iface": real})
            if project.id not in changed:
                changed.append(project.id)

    return changed
