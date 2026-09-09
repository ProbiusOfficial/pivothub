"""攻击机网络：GET / PUT /api/attack（任务 C-A）+ GET /api/netinfo（本机地址探测）。

攻击机在靶场网络中的地址是**所有回连命令的唯一来源**：Adapter 生成靶机命令、
链路登记 localSocks、新建项目攻击端节点都取这里；禁止写死 127.0.0.1。
"""

from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import DEFAULT_PROJECT_ID
from ..db import get_attack, get_db, set_attack
from ..models import Host
from ..schemas import AttackIn, AttackOut
from ..service import add_event
from ..ws import manager
from .deps import get_project
from ..localinfo import interfaces

router = APIRouter()


def _local_ipv4() -> list[str]:
    """本机非回环 IPv4（用于「攻击机就是面板所在机器」的地址自动检测）。

    过滤 127.* 与 169.254.*（链路本地）；私网地址排前，便于优先填入靶场地址。
    """

    def rank(ip: str) -> int:
        if ip.startswith("10."):
            return 0
        if ip.startswith("172."):
            try:
                if 16 <= int(ip.split(".")[1]) <= 31:
                    return 1
            except (ValueError, IndexError):
                pass
        if ip.startswith("192.168."):
            return 2
        if ip.startswith("169.254."):
            return 4
        return 3

    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = str(info[4][0])
            if ip not in ips and not ip.startswith(("127.", "169.254.")):
                ips.append(ip)
    except OSError:
        pass
    # 兜底：向外网「探测」一次拿默认出口地址（不实际发包，UDP connect 只做路由选择）
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 53))
                ip = s.getsockname()[0]
                if not ip.startswith(("127.", "169.254.")):
                    ips.append(ip)
            finally:
                s.close()
        except OSError:
            pass
    return sorted(ips, key=rank)


@router.get("/netinfo")
def netinfo():
    """面板所在机器的网络信息（攻击机地址检测 + 网卡/网段下拉框；只读，不产生任何连接）。"""
    return {
        "hostname": socket.gethostname(),
        "ips": _local_ipv4(),
        "interfaces": interfaces(),
    }


@router.get("/attack", response_model=AttackOut)
def read_attack(projectId: str = "", db: Session = Depends(get_db)):
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    return AttackOut(**get_attack(db, project.id))


@router.put("/attack", response_model=AttackOut)
def update_attack(form: AttackIn, projectId: str = "", db: Session = Depends(get_db)):
    """保存攻击机网络；同步攻击端本机节点（ip/segment/ifaces）与 WS 广播。"""
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    try:
        attack = set_attack(db, project.id, form.model_dump())
    except KeyError:
        raise HTTPException(404, f"项目不存在: {project.id}")

    local = (
        db.query(Host)
        .filter(Host.project_id == project.id, Host.is_local.is_(True))
        .first()
    )
    if local:
        local.ip = attack["ip"]
        local.segment = attack["segment"] or local.segment
        ifaces = list(local.ifaces or [])
        if ifaces:
            ifaces[0] = {
                "iface": attack.get("iface") or ifaces[0].get("iface", ""),
                "ip": attack["ip"],
                "segment": attack["segment"] or ifaces[0].get("segment", ""),
            }
        else:
            ifaces = [{
                "iface": attack.get("iface", ""),
                "ip": attack["ip"],
                "segment": attack.get("segment", ""),
            }]
        local.ifaces = ifaces
        if local.note:
            local.note = f"攻击端本机 · {attack.get('iface') or 'iface'} · {attack['ip']}"

    add_event(db, project.id, "note", f"攻击机网络更新为 {attack['ip']}",
              host_id=local.id if local else None,
              detail=f"{attack.get('iface') or '-'} · {attack.get('segment') or '-'} · 后续命令与链路地址已同步")
    db.commit()
    out = AttackOut(**attack)
    manager.push("attack.updated", attack=out.model_dump())
    return out
