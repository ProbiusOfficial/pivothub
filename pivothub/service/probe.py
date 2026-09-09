"""出网探测（M2 出网探测）：经会话层真实执行 ICMP / DNS / HTTP / TCP 四类探针。

设计要点：
- 全部经 SessionBase.exec 在目标侧真实执行，解析真实回显（路由层零 subprocess）；
- 返回结构对齐前端 proxy.js 的 detect 状态：verdict / recommend / alt / reason + 逐探针；
- 结论不伪造：探针失败如实标注，并给出降级建议（正向连接 / 复用上层代理）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..session.base import SessionBase

#: 默认探测目标（可在请求里覆盖）
DEFAULTS = {
    "icmpHost": "8.8.8.8",
    "dnsName": "www.baidu.com",
    "httpUrl": "http://www.baidu.com/",
    "tcpHost": "www.baidu.com",
    "tcpPort": 443,
}


@dataclass
class ProbeItem:
    key: str
    state: str = "idle"      # idle | run | ok | fail
    progress: int = 0
    ms: int = 0
    expect: str = "ok"
    cmd: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "state": self.state, "progress": self.progress,
                "ms": self.ms, "expect": self.expect, "cmd": self.cmd,
                "evidence": self.evidence}


@dataclass
class ProbeReport:
    hostId: str = ""
    verdict: str = ""
    recommend: str = ""
    alt: str = ""
    reason: str = ""
    probes: list[ProbeItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"hostId": self.hostId, "verdict": self.verdict, "recommend": self.recommend,
                "alt": self.alt, "reason": self.reason,
                "probes": [p.to_dict() for p in self.probes]}


def _cmd_icmp(host: str, platform: str) -> str:
    if platform == "windows":
        return f"ping -n 2 -w 2000 {host}"
    return f"ping -c 2 -W 2 {host} 2>&1"


def _cmd_dns(name: str, platform: str) -> str:
    if platform == "windows":
        return f"nslookup {name}"
    return f"(getent hosts {name} || nslookup {name} 2>&1 || host {name} 2>&1)"


def _cmd_http(url: str, platform: str) -> str:
    if platform == "windows":
        return ('powershell -NoP -NonI -Command "try{$r=Invoke-WebRequest -Uri ' + url
                + ' -UseBasicParsing -TimeoutSec 6; Write-Output (\\"HTTP \\" + $r.StatusCode)}'
                + 'catch{Write-Output \\"ERR $($_.Exception.Message)\\"}"')
    return (f"(curl -s -o /dev/null -m 6 -w 'HTTP %{{http_code}}' {url} 2>&1 || "
            f"wget -q -T 6 -O /dev/null --server-response {url} 2>&1 | head -n 3)")


def _cmd_tcp(host: str, port: int, platform: str) -> str:
    if platform == "windows":
        return ('powershell -NoP -NonI -Command "try{$c=New-Object Net.Sockets.TcpClient;'
                f'$c.Connect(\\"{host}\\",{port}); Write-Output \\"TCP OPEN\\"; $c.Close()}}'
                'catch{Write-Output \\"TCP CLOSED\\"}"')
    return (f"(timeout 5 bash -c 'exec 3<>/dev/tcp/{host}/{port} && echo TCP OPEN' 2>&1 "
            f"|| (echo > /dev/tcp/{host}/{port} 2>/dev/null && echo TCP OPEN) "
            f"|| echo TCP CLOSED)")


def _parse(key: str, output: str) -> tuple[bool, str]:
    """解析真实回显 → (是否可达, 证据片段)。不猜：只认明确标记。"""
    text = (output or "").strip()
    low = text.lower()
    if key == "ICMP":
        ok = bool(re.search(r"(ttl=|时间[<=]|time[<=]\s*\d|bytes from|来自.*的回复)", low)) \
            and "unreachable" not in low and "无法访问" not in text
        return ok, _first_line(text)
    if key == "DNS":
        ok = bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)) and "can't find" not in low \
            and "timed out" not in low and "not found" not in low and "找不到" not in text
        return ok, _first_line(text)
    if key == "HTTP":
        m = re.search(r"HTTP\s+(\d{3})", text)
        if m:
            return int(m.group(1)) < 500, text[:160]
        return ("err" not in low and "error" not in low and bool(text)), text[:160]
    if key == "TCP":
        return ("tcp open" in low), text[:160]
    return bool(text), text[:160]


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:160]
    return ""


def _compact_html(text: str, limit: int = 120) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]*>", "", text or "")).strip()[:limit]


def build_probes(platform: str, opts: dict) -> list[ProbeItem]:
    o = {**DEFAULTS, **(opts or {})}
    return [
        ProbeItem(key="ICMP", expect="fail", cmd=_cmd_icmp(str(o["icmpHost"]), platform)),
        ProbeItem(key="DNS", expect="ok", cmd=_cmd_dns(str(o["dnsName"]), platform)),
        ProbeItem(key="HTTP", expect="ok", cmd=_cmd_http(str(o["httpUrl"]), platform)),
        ProbeItem(key="TCP", expect="ok", cmd=_cmd_tcp(str(o["tcpHost"]), int(o["tcpPort"]), platform)),
    ]


def conclude(items: list[ProbeItem]) -> tuple[str, str, str, str]:
    """四探针结果 → (verdict, recommend, alt, reason)，与前端 finishDetect 语义一致。"""
    ok = {p.key: (p.state == "ok") for p in items}
    if ok.get("TCP") or ok.get("HTTP"):
        return ("可反向 TCP / HTTP 出网", "chisel（反向，单文件易上传）",
                "frp（反向 Socks5，链路更稳）",
                "TCP 与 HTTP 均可达：单跳用 chisel 一条命令搞定；需要长期稳定多级链时换 frp。")
    if ok.get("HTTP"):
        return ("仅 HTTP 出网", "Neo-reGeorg（HTTP 隧道）", "chisel over HTTP",
                "仅 80/443 可达，建议用 Neo-reGeorg 以 Web 请求承载 Socks5 流量。")
    if ok.get("DNS"):
        return ("仅 DNS 出网", "iodine / dnscat2（需外部工具编排）", "",
                "TCP/HTTP 均被阻断，仅 DNS 可出，需 DNS 隧道（一期仅提供推荐与编排提示）。")
    return ("未发现可用出网通道", "考虑正向连接（靶机不可出网，由攻击端主动连入）",
            "或通过已有 L1 代理向本段做正向转发",
            "四类探测全部失败，建议改用正向隧道或复用上层已建立的代理。")


def run_probes(session: SessionBase, host_id: str = "", opts: dict | None = None,
               per_timeout: float = 12.0) -> ProbeReport:
    """真实执行四类探针并给出结论（失败如实记录证据）。"""
    items = build_probes(getattr(session, "platform", "linux"), opts or {})
    for p in items:
        p.state = "run"
        res = session.exec(p.cmd, timeout=per_timeout)
        p.ms = int(getattr(res, "ms", 0) or 0)
        out = (res.output or "") + (("\n" + res.error) if getattr(res, "error", "") else "")
        ok, evidence = _parse(p.key, out)
        p.state = "ok" if ok else "fail"
        p.progress = 100
        p.evidence = _compact_html(evidence) or (res.error or "无回显")
    verdict, recommend, alt, reason = conclude(items)
    return ProbeReport(hostId=host_id, verdict=verdict, recommend=recommend, alt=alt,
                       reason=reason, probes=items)
