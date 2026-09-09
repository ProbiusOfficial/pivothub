"""适配器基类与部署结果。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..session.base import SessionBase

#: 链路类型（socks 代理 / 单端口转发 / 多级中继）
LINK_TYPES = ("socks", "portfwd", "relay")


@dataclass
class PidRecord:
    """链路各层进程：销毁时逐层清理，不留孤儿进程。"""

    pid: int
    role: str          # server | relay | target
    host_id: str = ""  # 该进程所在主机（'' = 攻击机本机）
    cmd: str = ""
    port: int = 0

    def to_dict(self) -> dict:
        return {"pid": self.pid, "role": self.role, "hostId": self.host_id,
                "cmd": self.cmd, "port": self.port}


@dataclass
class TunnelCheck:
    """隧道内真实性验证结果（连 <localPort> 读到目标服务回显）。"""

    ok: bool = False
    target: str = ""
    banner: str = ""
    ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "target": self.target, "banner": self.banner,
                "ms": self.ms, "error": self.error}


@dataclass
class DeployResult:
    ok: bool
    stage: str = ""            # platform | binary | server | upload | execute | wait_callback | verify | ...
    error: str = ""
    pid: Optional[int] = None  # 本机隧道服务端进程
    pids: list = field(default_factory=list)   # [PidRecord.to_dict(), ...] 逐层进程
    lhost: str = ""
    server_port: int = 0
    socks_port: int = 0
    local_port: int = 0
    remote_path: str = ""
    auth: str = ""
    link_type: str = "socks"
    hops: list = field(default_factory=list)
    verify: Optional[TunnelCheck] = None
    log: list = field(default_factory=list)

    def pid_dicts(self) -> list[dict]:
        return [p if isinstance(p, dict) else p.to_dict() for p in self.pids]


class AdapterBase:
    """统一生命周期接口。tool = 工具名（与前端工具表一致）。

    生命周期：generate_config → deploy（含 start/wait_callback）→ 路由层 register_link
    → health_check → destroy。
    """

    tool = "base"
    #: 支持的链路类型
    link_types = LINK_TYPES

    def generate_config(self, **kw) -> dict:
        raise NotImplementedError

    def deploy(self, session: SessionBase, **kw) -> DeployResult:
        raise NotImplementedError

    def health_check(self, link) -> bool:
        from ..util import proc_alive

        return proc_alive(getattr(link, "pid", None))

    def destroy(self, pid: Optional[int]) -> bool:
        from ..util import proc_kill

        return proc_kill(pid)

    def destroy_all(self, pids: list, session=None) -> list[dict]:
        """逐层清理：本机进程直接结束，远端进程经会话层结束。

        返回 [{pid, role, killed}]（不伪造成功：远端清理失败如实记录）。
        """
        out = []
        for item in (pids or []):
            rec = item if isinstance(item, dict) else item.to_dict()
            pid = rec.get("pid")
            killed = False
            if not pid:
                out.append({**rec, "killed": False})
                continue
            if rec.get("role") == "server" or not rec.get("hostId"):
                killed = self.destroy(pid)
            elif session is not None:
                try:
                    killed = bool(session.kill_pid(int(pid)))
                except Exception:
                    killed = False
            out.append({**rec, "killed": killed})
        return out
