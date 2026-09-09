"""导出服务：MD / HTML / JSON 三格式（数据全部来自 SQLite，凭据/口令按用户要求明文输出）。"""

from __future__ import annotations

import html as _html
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import Credential, Flag, Host, Project, ProxyLink, Shell, TimelineEvent
from ..service.statlib import project_stats
from ..service.timeline import segments_of

KIND_LABEL = {"shell": "Shell", "proxy": "代理", "host": "资产", "cred": "凭据", "flag": "Flag", "note": "笔记"}

DEFAULT_OPTS = {"topo": True, "chain": True, "timeline": True, "creds": True, "flags": True, "placeholder": True}


def _ip_of(hosts_by_id: dict, host_id: str | None) -> str:
    h = hosts_by_id.get(host_id)
    return h.ip if h else "—"


def build_markdown(db: Session, project_id: str, opts: dict | None = None) -> str:
    o = {**DEFAULT_OPTS, **(opts or {})}
    project = db.get(Project, project_id)
    hosts = db.query(Host).filter(Host.project_id == project_id).all()
    shells = db.query(Shell).filter(Shell.project_id == project_id).all()
    links = db.query(ProxyLink).filter(ProxyLink.project_id == project_id).all()
    creds = db.query(Credential).filter(Credential.project_id == project_id).all()
    flags = db.query(Flag).filter(Flag.project_id == project_id).all()
    timeline = (
        db.query(TimelineEvent).filter(TimelineEvent.project_id == project_id)
        .order_by(TimelineEvent.ts.asc(), TimelineEvent.id.asc()).all()
    )
    by_id = {h.id: h for h in hosts}
    segs = segments_of(hosts)
    stats = project_stats(hosts, shells, links, creds, flags, segs)

    p_name = project.name if project else project_id
    out = f"# {p_name} · Writeup\n\n"
    out += f"> 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n> 工具：PivotHub（链透中枢）· 本报告为初稿，需人工润色\n\n"
    out += "## 0. 概览\n\n| 指标 | 数值 |\n|---|---|\n"
    out += f"| 已控主机 | {stats['ownedHosts']} / {stats['hosts']} |\n"
    out += f"| 层级深度 | L1 → L{stats['maxLayer']} |\n"
    out += f"| 代理链路 | {stats['aliveLinks']} / {stats['links']} 存活 |\n"
    out += f"| 凭据 | {len(creds)} 条 |\n"
    out += f"| Flag | {len(flags)} |\n\n"

    if o["topo"]:
        out += "## 1. 网络拓扑\n\n```\n攻击端 127.0.0.1\n"
        for l in links:
            out += f"  └─[{l.tool} {l.direction} {l.local_socks or ''}]→ {_ip_of(by_id, l.from_host_id)}  ⇒  {l.target_segment or ''}\n"
        out += "```\n\n" + ("![拓扑快照](screenshots/topology.png)\n\n" if o["placeholder"] else "")

    if o["chain"]:
        out += "## 2. 跳板链参数\n\n| 工具 | 方向 | 入口 | 出口 | 本地 Socks | 目标网段 |\n|---|---|---|---|---|---|\n"
        for l in links:
            out += f"| {l.tool} | {l.direction} | {_ip_of(by_id, l.from_host_id)} | {_ip_of(by_id, l.to_host_id)} | {l.local_socks or '-'} | {l.target_segment or '-'} |\n"
        out += "\n"

    if o["timeline"]:
        out += "## 3. 操作时间线\n\n"
        for e in reversed(timeline):
            out += f"### {e.ts.strftime('%H:%M')} · {KIND_LABEL.get(e.kind, e.kind)} — {e.title}\n\n"
            if e.host_id:
                out += f"- 主机：`{_ip_of(by_id, e.host_id)}`\n"
            if e.detail:
                out += f"- {e.detail}\n"
            if e.cmd:
                out += f"\n```bash\n{e.cmd}\n```\n"
            if e.markdown:
                out += f"\n{e.markdown}\n"
            out += "\n"

    if o["creds"]:
        out += "## 4. 凭据清单（明文）\n\n| 账号 | 类型 | 凭据 | 来源主机 | 适用服务 |\n|---|---|---|---|---|\n"
        for c in creds:
            out += f"| `{c.username}` | {c.kind} | `{c.secret}` | {_ip_of(by_id, c.host_id)} | {','.join(c.services or [])} |\n"
        out += "\n"

    if o["flags"]:
        out += "## 5. Flag 收集\n\n| 主机 | 阶段 | Flag | 状态 |\n|---|---|---|---|\n"
        for f in flags:
            out += f"| {_ip_of(by_id, f.host_id)} | {f.stage} | `{f.value}` | {'已提交' if f.submitted else '待提交'} |\n"
        out += "\n"

    out += "## 6. 总结与反思\n\n> 待补充：本层关键突破点、踩坑与改进思路。\n"
    return out


def build_json(db: Session, project_id: str) -> str:
    import json

    project = db.get(Project, project_id)
    hosts = db.query(Host).filter(Host.project_id == project_id).all()
    shells = db.query(Shell).filter(Shell.project_id == project_id).all()
    links = db.query(ProxyLink).filter(ProxyLink.project_id == project_id).all()
    creds = db.query(Credential).filter(Credential.project_id == project_id).all()
    flags = db.query(Flag).filter(Flag.project_id == project_id).all()
    timeline = (
        db.query(TimelineEvent).filter(TimelineEvent.project_id == project_id)
        .order_by(TimelineEvent.ts.asc()).all()
    )
    segs = segments_of(hosts)
    stats = project_stats(hosts, shells, links, creds, flags, segs)

    payload = {
        "project": {
            "id": project.id, "name": project.name, "startAt": project.start_at,
            "durationSec": project.duration_sec, "note": project.note,
        } if project else {"id": project_id},
        "generatedAt": datetime.now().isoformat(),
        "stats": stats,
        "segments": segs,
        "hosts": [
            {
                "id": h.id, "ip": h.ip, "hostname": h.hostname, "os": h.os, "layer": h.layer,
                "segment": h.segment, "privilege": h.privilege, "owned": h.owned,
                "ports": h.ports, "services": h.services, "note": h.note,
                "discovery": h.discovery, "isLocal": h.is_local,
            }
            for h in hosts
        ],
        "shells": [{**_shell_dict(s), "pass": s.pwd} for s in shells],
        "proxyLinks": [
            {
                "id": l.id, "tool": l.tool, "direction": l.direction,
                "fromHostId": l.from_host_id, "toHostId": l.to_host_id,
                "localSocks": l.local_socks, "targetSegment": l.target_segment,
                "status": l.status, "latency": l.latency, "traffic": l.traffic,
                "conf": l.conf, "createdBy": l.created_by,
            }
            for l in links
        ],
        "credentials": [
            {
                "id": c.id, "hostId": c.host_id, "username": c.username, "secret": c.secret,
                "kind": c.kind, "services": c.services, "reuse": c.reuse, "source": c.source,
            }
            for c in creds
        ],
        "flags": [
            {"id": f.id, "hostId": f.host_id, "stage": f.stage, "value": f.value,
             "submitted": f.submitted, "time": f.created_at.strftime("%H:%M") if f.created_at else ""}
            for f in flags
        ],
        "timeline": [
            {
                "id": t.id, "time": t.ts.strftime("%H:%M") if t.ts else "", "kind": t.kind,
                "title": t.title, "hostId": t.host_id, "detail": t.detail,
                "cmd": t.cmd, "markdown": t.markdown,
            }
            for t in timeline
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _shell_dict(s: Shell) -> dict:
    return {
        "id": s.id, "hostId": s.host_id, "type": s.type, "url": s.url,
        "encoder": s.encoder, "alive": s.alive, "latency": s.latency,
        "hostname": s.hostname, "privilege": s.privilege, "stable": s.stable,
    }


def build_html(md_text: str, project_name: str) -> str:
    """与前端 export.js buildHtml 同构的暗色 HTML 报告。"""
    body = _html.escape(md_text)
    return (
        "<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\" />\n"
        f"<title>{_html.escape(project_name)} · PivotHub 报告</title>\n"
        "<style>body{background:#070b0f;color:#d7e4ec;font-family:system-ui,\"PingFang SC\",sans-serif;"
        "max-width:900px;margin:0 auto;padding:32px;line-height:1.7}"
        "h1,h2{color:#00e5a0}code,pre{font-family:Consolas,monospace;background:#0e161d;color:#a8f0d3;"
        "padding:2px 5px;border-radius:3px}"
        "pre{padding:12px;overflow:auto;border:1px solid #1d2b37}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #1d2b37;padding:6px 9px;text-align:left}"
        "blockquote{border-left:3px solid #00e5a0;margin:0;padding-left:12px;color:#8ba0ae}</style></head>\n"
        f"<body>\n<pre>{body}</pre>\n</body></html>"
    )
