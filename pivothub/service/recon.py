"""资产探测：内网信息收集与扫描结果解析。

纯函数为主（便于单测），API 层只负责开会话 / 执行 / 落库：
  ① env_command      → 网卡 / /etc/hosts / 路由 / ARP 分段回显
  ② scanner_command  → 上传扫描器后的执行命令（fscan 风格模板）
     builtin_command → 无扫描器时的轻量探测（ping 存活 + /dev/tcp 端口）
  ③ parse_scan_output→ 兼容 fscan / nmap（normal + grepable）/ 内置探测的输出
"""

from __future__ import annotations

import base64
import ipaddress
import re
import shlex
from typing import Any

IP = r"\d{1,3}(?:\.\d{1,3}){3}"
IP_RE = re.compile(rf"^{IP}$")
IP_ANY_RE = re.compile(rf"\b({IP})\b")

#: 分段回显标记（命令里 echo 这些字符串，输出按标记切段）
MARKERS = ("---IPADDR---", "---HOSTS---", "---ROUTE---", "---ARP---", "---END---")

#: 默认扫描端口（fscan -p 同款）
DEFAULT_PORTS = "21,22,80,135,139,443,445,1433,1521,3306,3389,5432,6379,8080,8443,10000"

#: 扫描器命令模板占位符：{SCANNER} {SEGMENT} {PORTS} {EXTRA}
DEFAULT_TEMPLATE = "{SCANNER} -h {SEGMENT} -p {PORTS} {EXTRA}"
#: fscan 默认模板（-nobr 关爆破：资产探测阶段只要端口/服务/标题，快且安静）
FSCAN_TEMPLATE = "{SCANNER} -h {SEGMENT} -p {PORTS} -nobr {EXTRA}"

#: 常见端口 → 服务名（识别不到时按端口区间给个大概）
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos", 110: "POP3",
    111: "rpcbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTrap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "kpasswd", 465: "SMTPS", 500: "IKE",
    514: "Syslog", 515: "LPD", 548: "AFP", 554: "RTSP", 587: "SMTP-Submission",
    623: "IPMI", 631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS",
    995: "POP3S", 1025: "MSRPC-Alt", 1080: "SOCKS", 1099: "RMI", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL-Monitor", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP",
    1883: "MQTT", 1900: "SSDP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2181: "ZooKeeper", 2222: "SSH-Alt", 2375: "Docker", 2376: "Docker-TLS",
    2379: "etcd", 3128: "Squid", 3260: "iSCSI", 3306: "MySQL", 3389: "RDP",
    4440: "Rundeck", 4848: "GlassFish", 5000: "HTTP-Alt/Docker-Registry",
    5432: "PostgreSQL", 5555: "ADB", 5037: "ADB", 5601: "Kibana", 5672: "AMQP", 5900: "VNC",
    5901: "VNC-1", 5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6000: "X11", 6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic",
    7002: "WebLogic-SSL", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
    8080: "HTTP-Proxy/Alt", 8081: "HTTP-Alt", 8082: "HTTP-Alt", 8086: "InfluxDB",
    8088: "Hadoop-YARN", 8090: "HTTP-Alt", 8161: "ActiveMQ", 8180: "HTTP-Alt",
    8443: "HTTPS-Alt", 8529: "ArangoDB", 8888: "HTTP-Alt/Jupyter", 8983: "Solr",
    9000: "HTTP-Alt/SonarQube", 9001: "HTTP-Alt", 9042: "Cassandra", 9090: "HTTP-Alt",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "ES-Transport", 9443: "HTTPS-Alt",
    10000: "Webmin", 10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP", 50070: "HDFS-NameNode",
    61616: "ActiveMQ-OpenWire",
}

#: 需要抓 Web 标题的端口（HTTP/HTTPS 常见口）
WEB_PORTS = {
    80, 81, 88, 443, 888, 3000, 5000, 5601, 6001, 7001, 7002, 8000, 8008, 8080,
    8081, 8082, 8088, 8089, 8090, 8161, 8180, 8443, 8888, 8983, 9000, 9001, 9080,
    9090, 9200, 9443, 10000, 15672,
}
#: 默认按 TLS 直连的端口（其余先试 http 再试 https）
TLS_PORTS = {443, 8443, 9443, 6443, 7443, 8006, 8843}


def service_of(port: int) -> str:
    """端口 → 服务名；未收录时按区间给个大概。"""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    if port < 1024:
        return "unknown"
    if port < 10000:
        return "high-port"
    return "dynamic-port"


#: fscan 回显里常见的服务标记 → 标准服务名
_SERVICE_ALIASES = {
    "http": "HTTP", "https": "HTTPS", "ssl": "HTTPS", "ssh": "SSH",
    "mysql": "MySQL", "mssql": "MSSQL", "redis": "Redis", "smb": "SMB",
    "rdp": "RDP", "ftp": "FTP", "smtp": "SMTP", "ldap": "LDAP", "vnc": "VNC",
    "mongodb": "MongoDB", "postgres": "PostgreSQL", "postgresql": "PostgreSQL",
    "mqtt": "MQTT", "adb": "ADB", "docker": "Docker", "tomcat": "Tomcat",
    "nginx": "nginx", "apache": "Apache", "iis": "IIS", "weblogic": "WebLogic",
    "elasticsearch": "Elasticsearch", "memcached": "Memcached", "zookeeper": "ZooKeeper",
}


def env_command(platform: str) -> str:
    """信息收集命令：一次执行拿网卡 / hosts / 路由 / ARP（按标记分段）。"""
    if platform == "windows":
        # chcp 65001：中文 Windows 控制台默认 GBK，先切 UTF-8 避免回显乱码
        return (
            "chcp 65001 >nul & echo ---IPADDR--- & ipconfig /all & echo ---HOSTS--- & "
            "type %SystemRoot%\\System32\\drivers\\etc\\hosts & echo ---ROUTE--- & "
            "route print & echo ---ARP--- & arp -a & echo ---END---"
        )
    return (
        "echo ---IPADDR---; (ip -o -4 addr show 2>/dev/null || ifconfig -a 2>/dev/null); "
        "echo ---HOSTS---; cat /etc/hosts 2>/dev/null; "
        "echo ---ROUTE---; (ip route 2>/dev/null || route -n 2>/dev/null); "
        "echo ---ARP---; (ip neigh 2>/dev/null || arp -a 2>/dev/null); "
        "echo ---END---"
    )


def split_sections(text: str) -> dict[str, str]:
    """按 MARKERS 把回显切成 {段名: 内容}；找不到标记时整段归入 ipaddr。"""
    out: dict[str, str] = {}
    cur = ""
    for line in (text or "").splitlines():
        hit = next((m for m in MARKERS if m in line), None)
        if hit:
            cur = hit.strip("-").lower()
            out.setdefault(cur, "")
            continue
        if cur:
            out[cur] += line + "\n"
    if not out:
        out["ipaddr"] = text or ""
    return out


def _prefix_of(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ipaddress.NetmaskValueError, ValueError):
        return 24


def _seg(ip: str, prefix: int) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ""


def _iface_entry(iface: str, ip: str, prefix: int) -> dict[str, Any]:
    return {"iface": iface, "ip": ip, "prefix": prefix, "segment": _seg(ip, prefix)}


def parse_interfaces(text: str, platform: str = "linux") -> list[dict]:
    """解析 `ip -o -4 addr` / `ifconfig -a` / `ipconfig /all` 的网卡列表。"""
    out: list[dict] = []
    for m in re.finditer(rf"^\s*\d+:\s+(\S+)\s+inet\s+({IP})/(\d{{1,2}})", text, re.M):
        out.append(_iface_entry(m.group(1), m.group(2), int(m.group(3))))
    if not out:
        cur = ""
        for line in text.splitlines():
            m = re.match(r"^(\S+?)[:\s].*flags=", line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^(\S+)\s+Link encap", line)  # 老式 ifconfig
            if m:
                cur = m.group(1)
                continue
            m2 = re.search(rf"inet\s+(?:addr:)?({IP})\s+(?:netmask|Mask:)\s*({IP})", line)
            if m2 and cur:
                out.append(_iface_entry(cur, m2.group(1), _prefix_of(m2.group(2))))
    if not out and platform == "windows":
        cur = ""
        pending_ip = ""
        for line in text.splitlines():
            m = re.search(r"(?:adapter|适配器)\s+(.+?):\s*$", line)
            if m:
                cur = m.group(1).strip()
                pending_ip = ""
                continue
            m2 = re.search(rf"IPv4[^:]*:\s*({IP})", line)
            if m2:
                pending_ip = m2.group(1)
                continue
            m3 = re.search(rf"(?:Subnet Mask|子网掩码)[^:]*:\s*({IP})", line)
            if m3 and pending_ip:
                out.append(_iface_entry(cur or "iface", pending_ip, _prefix_of(m3.group(1))))
                pending_ip = ""
    # 去重（同网卡同 IP）
    seen: set[tuple[str, str]] = set()
    uniq: list[dict] = []
    for e in out:
        key = (e["iface"], e["ip"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    return uniq


def parse_hosts_file(text: str) -> list[dict]:
    """解析 /etc/hosts（含 Windows hosts）：{ip, names[]}。"""
    out: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if not IP_RE.match(parts[0]):
            continue
        out.append({"ip": parts[0], "names": parts[1:]})
    return out


def parse_routes(text: str) -> list[dict]:
    """解析 `ip route` / `route -n` / Windows `route print` 的关键路由。"""
    out: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        # ip route 风格：default via 10.8.0.1 dev tun0 / 10.0.0.0/24 dev eth1 scope link
        if line == "default" or line.startswith("default ") or re.match(rf"^{IP}/\d+\s", line):
            via = re.search(rf"via\s+({IP})", line)
            dev = re.search(r"dev\s+(\S+)", line)
            out.append({"dst": line.split()[0], "via": via.group(1) if via else "",
                        "dev": dev.group(1) if dev else ""})
            continue
        parts = line.split()
        if len(parts) >= 8 and IP_RE.match(parts[0]) and IP_RE.match(parts[1]):
            # Linux route -n: Destination Gateway Genmask Flags Metric Ref Use Iface
            out.append({"dst": parts[0], "via": parts[1], "dev": parts[-1]})
            continue
        if len(parts) == 5 and IP_RE.match(parts[0]) and IP_RE.match(parts[3]):
            # Windows route print: Destination Netmask Gateway Interface Metric
            out.append({"dst": parts[0], "via": parts[2], "dev": parts[3]})
    # 去重
    seen: set[tuple[str, str]] = set()
    uniq: list[dict] = []
    for r in out:
        key = (r["dst"], r["via"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    return uniq


def parse_arp(text: str) -> list[dict]:
    """解析 `ip neigh` / `arp -a`（Linux 与 Windows 两种格式）。"""
    out: list[dict] = []
    for line in (text or "").splitlines():
        m = re.search(rf"^({IP})\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?", line.strip())
        if m:
            out.append({"ip": m.group(1), "iface": m.group(2), "mac": m.group(3) or ""})
            continue
        m2 = re.search(rf"\(({IP})\)\s+at\s+(\S+)", line)
        if m2:
            out.append({"ip": m2.group(1), "iface": "", "mac": m2.group(2)})
            continue
        m3 = re.search(rf"^\s*({IP})\s+([0-9a-fA-F-]{{11,17}})\s+\S+", line)
        if m3:
            out.append({"ip": m3.group(1), "iface": "", "mac": m3.group(2)})
    return out


def segments_of(ifaces: list[dict], routes: list[dict] | None = None) -> list[str]:
    """从网卡（+ 路由目标网段）汇总可扫描网段，去重保序，排除回环 / 链路本地。"""
    out: list[str] = []

    def keep(seg: str) -> bool:
        try:
            net = ipaddress.ip_network(seg, strict=False)
        except ValueError:
            return False
        return not (net.is_loopback or net.is_link_local or net.is_multicast
                    or net.is_unspecified)

    for e in ifaces:
        seg = e.get("segment") or ""
        if seg and seg not in out and keep(seg):
            out.append(seg)
    for r in (routes or []):
        dst = r.get("dst") or ""
        if "/" not in dst or dst == "0.0.0.0/0" or dst in out:
            continue
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if net.num_addresses <= 4096 and keep(str(net)):  # 太大的段不默认纳入扫描
            out.append(str(net))
    return out


# ---------------------------------------------------------------------------
# 扫描命令与结果解析
# ---------------------------------------------------------------------------

def quote_path(path: str, platform: str) -> str:
    return f'"{path}"' if platform == "windows" else shlex.quote(path)


def service_name(token: str, port: int = 0) -> str:
    """扫描器回显里的服务标记 → 规范服务名；空标记回落端口表。"""
    t = (token or "").strip().lower()
    if t in _SERVICE_ALIASES:
        return _SERVICE_ALIASES[t]
    if t and t not in ("open", "alive", "up"):
        return token.strip()[:24]
    return service_of(port) if port else ""


def web_title_command(targets: list[str], platform: str = "linux", timeout: int = 5) -> str:
    """目标侧抓 Web 标题：优先 curl（含 https），退 wget。

    输出 `PIVOTHUB_TITLE ip:port <base64(标题)>`——标题常是中文，而 HTTP 马回显会经
    JVM/响应编码转换（非 ASCII 变 `?`），base64 是 ASCII，能原样穿过任何字符集。
    targets = ["10.0.0.5:80", ...]；目标在网段内可达，由目标自己发请求。
    """
    if platform == "windows" or not targets:
        return ""
    items = " ".join(targets[:40])  # 控制命令长度
    t = str(int(timeout))
    return "".join([
        "for t in ", items, "; do ( ",
        "ip=${t%:*}; port=${t#*:}; scheme=http; ",
        "case $port in 443|8443|9443|6443|7443|8006|8843) scheme=https;; esac; ",
        "body=''; ",
        "if command -v curl >/dev/null 2>&1; then ",
        'body=$(curl -sk -m ', t, ' -o - "$scheme://$ip:$port/" 2>/dev/null | head -c 8192); ',
        '[ -z "$body" ] && body=$(curl -sk -m ', t,
        ' -o - "https://$ip:$port/" 2>/dev/null | head -c 8192); ',
        "elif command -v wget >/dev/null 2>&1; then ",
        'body=$(wget -q -T ', t, ' -O - "$scheme://$ip:$port/" 2>/dev/null | head -c 8192); ',
        "fi; ",
        'title=$(printf \'%s\' "$body" | tr -d "\\r\\n" | '
        "sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee]>[[:space:]]*\\([^<]*\\)<.*/\\1/p' | head -c 200); ",
        '[ -n "$title" ] && echo "PIVOTHUB_TITLE $t $(printf \'%s\' "$title" | base64 | tr -d \'\\n\')"; ',
        ") & done; wait",
    ])


def parse_title_output(text: str) -> dict[str, str]:
    """解析 `PIVOTHUB_TITLE ip:port <base64|明文>` → {"ip:port": 标题}。"""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        m = re.search(rf"PIVOTHUB_TITLE\s+({IP}:\d{{1,5}})\s+(\S+)\s*$", line.strip())
        if not m:
            continue
        raw = m.group(2)
        title = raw
        if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", raw):
            try:
                title = base64.b64decode(raw).decode("utf-8", "replace")
            except Exception:
                title = raw
        out[m.group(1)] = title.strip()[:120]
    return out


def web_targets(hosts: list[dict], limit: int = 40) -> list[str]:
    """挑出需要抓标题的 Web 端口：没有标题的，以及标题明显被字符集弄坏（?/�）的。"""
    out: list[str] = []
    for h in hosts:
        for info in (h.get("portInfo") or []):
            if info.get("port") not in WEB_PORTS:
                continue
            title = info.get("title") or ""
            if not title or "?" in title or "\ufffd" in title:
                out.append(f"{h['ip']}:{info['port']}")
    return out[:limit]


def scanner_command(scanner_path: str, segment: str, ports: str,
                    extra: str = "", template: str = "", platform: str = "linux") -> str:
    """按模板拼扫描器命令（默认 fscan 兼容：`<scanner> -h <seg> -p <ports>`）。"""
    tpl = (template or "").strip() or DEFAULT_TEMPLATE
    return (tpl.replace("{SCANNER}", quote_path(scanner_path, platform))
               .replace("{SEGMENT}", segment)
               .replace("{PORTS}", ports)
               .replace("{EXTRA}", (extra or "").strip())).strip()


def builtin_command(segment: str, ports: str, platform: str = "linux") -> str:
    """无扫描器时的轻量探测：ping 存活 + /dev/tcp 端口探测（仅 Linux）。"""
    if platform == "windows":
        return ""
    try:
        net = ipaddress.ip_network(segment, strict=False)
    except ValueError:
        return ""
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 254:
        return ""
    port_list = " ".join(p for p in str(ports).replace(",", " ").split() if p.isdigit())
    ips = " ".join(hosts)
    return (
        f"ports='{port_list}'; "
        f"for ip in {ips}; do ( "
        f"ping -c1 -W1 $ip >/dev/null 2>&1 || exit 0; "
        f"echo \"$ip alive\"; "
        f"for p in $ports; do (timeout 1 bash -c \"echo >/dev/tcp/$ip/$p\" 2>/dev/null "
        f"&& echo \"$ip:$p open\"); done ) & done; wait"
    )


def parse_scan_output(text: str) -> list[dict]:
    """解析扫描回显 → [{ip, ports[], portInfo[], hostname, note}]。

    兼容 fscan v1/v2、nmap（normal + grepable）与内置探测；端口带服务名，
    Web 端口带页面标题（来自 fscan 的 webtitle 插件或后续目标侧补充探测）。
    """
    found: dict[str, dict] = {}

    def add(ip: str, port: int | None = None, hostname: str = "", note: str = "",
            title: str = "", service: str = "") -> None:
        if not IP_RE.match(ip):
            return
        item = found.setdefault(ip, {
            "ip": ip, "ports": [], "hostname": "", "note": "",
            "_services": {}, "_titles": {},
        })
        if port:
            if port not in item["ports"]:
                item["ports"].append(port)
            if service:
                item["_services"][port] = service
            if title:
                item["_titles"][port] = title
        if hostname and not item["hostname"]:
            item["hostname"] = hostname
        if note and note not in item["note"]:
            item["note"] = (item["note"] + " " + note).strip()

    current = ""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # fscan v2 web 标题：[*] http://10.0.0.5:80  code:200 len:123 title:XXX server:nginx
        m = re.search(rf"https?://({IP})(?::(\d{{1,5}}))?[^\n]*?title[:：]\s*(.+)$", line, re.I)
        if m:
            tail = m.group(3).strip()
            srv = ""
            ms = re.search(r"\bserver:(\S+)", tail)
            if ms:
                srv = ms.group(1)
                tail = tail[:ms.start()].strip()
            add(m.group(1), int(m.group(2) or 80), title=tail[:120], service=srv)
            continue
        # fscan v2 指纹行：[*] http://10.0.0.5:8080  dps-shell [Product:XXX] Banner:(...)
        m = re.search(rf"https?://({IP})(?::(\d{{1,5}}))?\s+([^\[]*)\[Product:([^\]]+)\]", line)
        if m:
            add(m.group(1), int(m.group(2) or 80),
                service=m.group(4).strip()[:40], note=m.group(3).strip())
            continue
        # fscan v2 开放端口：[*] 10.0.0.5:1883   mqtt
        m = re.match(rf"^\[[+\-*]\]\s+({IP}):(\d{{1,5}})\s*(\S*)\s*$", line)
        if m:
            add(m.group(1), int(m.group(2)), service=service_name(m.group(3), int(m.group(2))))
            continue
        # fscan v2 非 http 指纹行（带产品信息，行尾还有 Banner）：
        # [*] 10.0.0.5:22   ssh   [Product:OpenSSH ||Version:9.2p1] Banner:(...)
        m = re.match(rf"^\[[+\-*]\]\s+({IP}):(\d{{1,5}})\s+(\S+)\s+\[Product:([^\]]*)\]", line)
        if m:
            add(m.group(1), int(m.group(2)),
                service=service_name(m.group(3), int(m.group(2))),
                note=m.group(4).strip()[:60])
            continue
        # nmap normal: Nmap scan report for web01 (10.0.0.5)
        m = re.search(rf"Nmap scan report for (?:(\S+)\s+\()?({IP})\)?", line)
        if m:
            current = m.group(2)
            add(current, hostname=m.group(1) or "")
            continue
        m = re.match(r"^(\d{1,5})/(?:tcp|udp)\s+open\s*(\S*)", line)
        if m and current:
            add(current, int(m.group(1)), service=service_name(m.group(2), int(m.group(1))))
            continue
        # nmap grepable: Host: 10.0.0.5 () Ports: 80/open/tcp//http/
        m = re.search(rf"Host:\s*({IP})\s*\(\s*\)\s*Ports:\s*([^\t]+)", line)
        if m:
            add(m.group(1))
            for p in re.finditer(r"(\d+)/open/\w+//([^,/]*)", m.group(2)):
                add(m.group(1), int(p.group(1)), service=service_name(p.group(2), int(p.group(1))))
            continue
        # 内置 / 旧 fscan：10.0.0.5:22 open http
        m = re.search(rf"({IP}):(\d{{1,5}})\s+open\b(.*)$", line)
        if m:
            tail = m.group(3).strip().split()
            add(m.group(1), int(m.group(2)), note=tail[0] if tail else "",
                service=service_name(tail[0] if tail else "", int(m.group(2))))
            continue
        # fscan Alive / 内置 alive
        m = re.search(rf"({IP})\s+(?:alive|up)\b", line, re.I)
        if m:
            add(m.group(1), note="存活")
            continue
        # fscan v2 中文输出：`[*] 172.33.0.10 存活 (来源: ICMP)`
        m = re.search(rf"({IP})\s*存活", line)
        if m:
            add(m.group(1), note="存活")
            continue
        m = re.search(rf"Alive:\s*({IP})", line, re.I)
        if m:
            add(m.group(1), note="存活")

    out: list[dict] = []
    for item in found.values():
        last = item["ip"].rsplit(".", 1)[-1]
        if last in ("0", "255"):  # 网络号 / 广播地址不算资产
            continue
        item["ports"] = sorted(item["ports"])
        services, titles = item.pop("_services"), item.pop("_titles")
        item["portInfo"] = [
            {"port": p, "service": services.get(p) or service_of(p), "title": titles.get(p, "")}
            for p in item["ports"]
        ]
        out.append(item)
    return sorted(out, key=lambda x: tuple(int(n) for n in x["ip"].split(".")))
