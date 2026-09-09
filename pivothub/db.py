"""数据库基础设施：engine / session / Base / init_db（含播种）。"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from . import config

log = logging.getLogger("pivothub.db")


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine():
    global _engine
    if _engine is None:
        config.ensure_dirs()
        _engine = create_engine(config.DB_URL, connect_args={"check_same_thread": False})

        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    return _SessionLocal


def get_db():
    """FastAPI 依赖：每请求一个会话。"""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_meta() -> dict:
    return _load_json(config.DATA_DIR / "meta.json")


def load_seed_project() -> dict:
    return _load_json(config.DATA_DIR / "seed_project.json")


def default_attack() -> dict:
    """攻击机网络默认值（来源 data/meta.json 基线）。"""
    meta = load_meta()
    a = dict(meta.get("attack") or {})
    a.setdefault("ip", "192.0.2.10")
    a.setdefault("segment", "192.0.2.0/24")
    a.setdefault("iface", "tun0")
    a.setdefault("note", "攻击端通过 VPN 接入靶场网络")
    return a


def get_attack(db, project_id: str) -> dict:
    """读取项目级攻击机网络配置；未设置时回落到 data/meta.json 基线。"""
    from .models import Project

    p = db.get(Project, project_id)
    if p is not None:
        cfg = (p.settings or {}).get("attack")
        if cfg and cfg.get("ip"):
            merged = default_attack()
            merged.update({k: v for k, v in cfg.items() if v is not None})
            return merged
    return default_attack()


def set_attack(db, project_id: str, attack: dict) -> dict:
    from .models import Project

    p = db.get(Project, project_id)
    if p is None:
        raise KeyError(project_id)
    merged = default_attack()
    merged.update({k: v for k, v in (attack or {}).items() if v is not None})
    settings = dict(p.settings or {})
    settings["attack"] = merged
    p.settings = settings
    return merged


def tool_catalog() -> list[dict]:
    """代理工具目录（data/meta.json → tools）；缺 status 视为下线。"""
    out: list[dict] = []
    for t in load_meta().get("tools", []):
        item = dict(t)
        item.setdefault("status", "offline")
        out.append(item)
    return out


def default_enabled_tools() -> list[str]:
    """默认启用集 = 已接入适配器的工具（status=online）。"""
    return [t["name"] for t in tool_catalog() if t.get("status") == "online"]


def get_tools(db, project_id: str) -> list[dict]:
    """目录 + 项目级启用标记；下线工具永远 enabled=False（MS4 仅 chisel）。"""
    from .models import Project

    catalog = tool_catalog()
    online = {t["name"] for t in catalog if t.get("status") == "online"}
    enabled = default_enabled_tools()
    p = db.get(Project, project_id)
    if p is not None:
        cfg = (p.settings or {}).get("tools")
        if isinstance(cfg, dict) and isinstance(cfg.get("enabled"), list):
            enabled = [str(x) for x in cfg["enabled"]]
    enabled = [n for n in enabled if n in online]
    for t in catalog:
        t["enabled"] = bool(t["name"] in enabled)
    return catalog


def set_tools(db, project_id: str, enabled: list[str]) -> list[dict]:
    """写入项目级启用集；未知工具或未接入（offline）工具拒绝。"""
    from .models import Project

    p = db.get(Project, project_id)
    if p is None:
        raise KeyError(project_id)
    catalog = {t["name"]: t for t in tool_catalog()}
    unknown = [n for n in enabled if n not in catalog]
    if unknown:
        raise ValueError(f"未知工具: {', '.join(unknown)}")
    offline = [n for n in enabled if catalog[n].get("status") != "online"]
    if offline:
        raise ValueError(f"工具适配器尚未接入，无法启用: {', '.join(offline)}（当前仅 chisel）")
    settings = dict(p.settings or {})
    settings["tools"] = {"enabled": sorted(set(enabled))}
    p.settings = settings
    return get_tools(db, project_id)


def load_plugin_dir(sub: str) -> list[dict]:
    """读取 data/<sub>/*.json 插件目录（命令库/马模板/固化技法）。"""
    items: list[dict] = []
    d = config.DATA_DIR / sub
    if not d.is_dir():
        return items
    for p in sorted(d.glob("*.json")):
        data = _load_json(p)
        if isinstance(data, list):
            items.extend(data)
        else:
            items.append(data)
    return items


def init_db(seed: bool = True) -> None:
    """建表；若库为空且 seed=True，则播种演示项目（三层内网场景）。"""
    from . import models  # noqa: F401  确保模型注册

    engine = get_engine()
    Base.metadata.create_all(engine)
    _migrate_columns(engine)
    if not seed:
        return
    with get_session_factory()() as db:
        if db.query(models.Project).count() > 0:
            return
        _seed(db)
        db.commit()
        log.info("已播种演示项目（三层内网 CTF 场景）")


#: 轻量迁移：老库（上一版 schema）缺少的新增列 → 直接 ALTER TABLE 补上
_MIGRATIONS: dict[str, dict[str, str]] = {
    "projects": {"settings": "JSON"},
    "hosts": {"ifaces": "JSON"},
    "shells": {"kind": "VARCHAR(16) DEFAULT ''"},
    "proxy_links": {
        "link_type": "VARCHAR(16) DEFAULT 'socks'",
        "listen_port": "INTEGER DEFAULT 0",
        "remote_bind": "VARCHAR(64) DEFAULT ''",
        "local_port": "INTEGER DEFAULT 0",
        "target_host": "VARCHAR(64) DEFAULT ''",
        "target_port": "INTEGER DEFAULT 0",
        "relay_addr": "VARCHAR(64) DEFAULT ''",
        "relay_port": "INTEGER DEFAULT 0",
        "hops": "JSON",
        "pids": "JSON",
    },
}


def _migrate_columns(engine) -> None:
    """为已存在的旧库补列（SQLite 的 create_all 不会改表）。"""
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, cols in _MIGRATIONS.items():
            if table not in existing_tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for col, ddl in cols.items():
                if col in have:
                    continue
                conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{col}" {ddl}'))
                log.info("迁移：%s 新增列 %s", table, col)


def _seed(db: Session) -> None:
    from . import models

    seed = load_seed_project()
    meta = load_meta()

    for p in seed["projects"]:
        if p["id"] != seed["project"]["id"]:
            db.add(models.Project(id=p["id"], name=p["name"], settings={}))
    proj = seed["project"]
    db.add(
        models.Project(
            id=proj["id"], name=proj["name"], start_at=proj.get("startAt", "10:00"),
            duration_sec=proj.get("durationSec", 4 * 3600), note=proj.get("note", ""),
            settings={"attack": default_attack()},
        )
    )

    info = None
    for h in seed["hosts"]:
        hostname = h.get("hostname", "")
        os_name = h.get("os", "")
        privilege = h.get("privilege", "")
        note = h.get("note", "")
        ifaces = h.get("ifaces", [])
        if h.get("isLocal"):
            # 本机节点用真实运行环境覆盖种子里的演示值（Kali / eth0 / root）
            from .localinfo import iface_for, machine

            info = info or machine()
            hostname, os_name, privilege = info["hostname"], info["os"], info["privilege"]
            iface = iface_for(h["ip"]) or (ifaces[0].get("iface", "") if ifaces else "")
            ifaces = [{"iface": iface, "ip": h["ip"], "segment": h.get("segment", "")}]
            note = f"攻击端本机（{iface or 'iface'} · {h['ip']}）· 面板运行位置"
        db.add(
            models.Host(
                id=h["id"], project_id=proj["id"], ip=h["ip"], hostname=hostname,
                os=os_name, layer=h.get("layer", "L1"), segment=h.get("segment", ""),
                privilege=privilege, owned=bool(h.get("owned")),
                ports=h.get("ports", []), services=h.get("services", []),
                note=note, discovery=h.get("discovery", ""),
                is_local=bool(h.get("isLocal")), ifaces=ifaces,
            )
        )

    for s in seed["shells"]:
        db.add(
            models.Shell(
                id=s["id"], project_id=proj["id"], host_id=s["hostId"], type=s["type"],
                url=s["url"], pwd=s.get("pass", ""), encoder=s.get("encoder", "none"),
                alive=bool(s.get("alive")), latency=int(s.get("latency", 0)),
                last_beat_at=None, hostname=s.get("hostname", ""),
                privilege=s.get("privilege", ""), stable=bool(s.get("stable")),
            )
        )

    for l in seed["links"]:
        db.add(
            models.ProxyLink(
                id=l["id"], project_id=proj["id"], tool=l["tool"],
                link_type=l.get("linkType", "socks"), direction=l["direction"],
                from_host_id=l["fromHostId"], to_host_id=l["toHostId"],
                local_socks=l.get("localSocks", ""), target_segment=l.get("targetSegment", ""),
                status=l.get("status", "stopped"), latency=int(l.get("latency", 0)),
                traffic=l.get("traffic", "0 B"), conf=l.get("conf", ""),
                created_by=l.get("createdBy", "半自动档"), note=l.get("note", ""),
                listen_port=int(l.get("listenPort", 0) or 0),
                remote_bind=l.get("remoteBind", ""), local_port=int(l.get("localPort", 0) or 0),
                target_host=l.get("targetHost", ""), target_port=int(l.get("targetPort", 0) or 0),
                relay_addr=l.get("relayAddr", ""), relay_port=int(l.get("relayPort", 0) or 0),
                hops=l.get("hops", []), pids=[],
            )
        )

    base_time = datetime.now().replace(hour=10, minute=12, second=0, microsecond=0)
    for i, t in enumerate(seed["timeline"]):
        hh, mm = t["time"].split(":")
        ts = base_time.replace(hour=int(hh), minute=int(mm))
        db.add(
            models.TimelineEvent(
                id=t["id"], project_id=proj["id"], ts=ts, kind=t["kind"], title=t["title"],
                host_id=t.get("hostId"), detail=t.get("detail", ""), cmd=t.get("cmd", ""),
                markdown=t.get("markdown", ""),
            )
        )

    for c in seed["creds"]:
        hh, mm = c["time"].split(":")
        ts = base_time.replace(hour=int(hh), minute=int(mm))
        db.add(
            models.Credential(
                id=c["id"], project_id=proj["id"], host_id=c["hostId"], username=c["username"],
                secret=c["secret"], kind=c["kind"], services=c.get("services", []),
                reuse=bool(c.get("reuse")), source=c.get("source", ""), created_at=ts,
            )
        )

    for f in seed["flags"]:
        hh, mm = f["time"].split(":")
        ts = base_time.replace(hour=int(hh), minute=int(mm))
        db.add(
            models.Flag(
                id=f["id"], project_id=proj["id"], host_id=f["hostId"], stage=f["stage"],
                value=f["value"], submitted=bool(f.get("submitted")), created_at=ts,
            )
        )

    # meta 里保留的演示期段配置落库（segments 表不存在，序列化时按主机聚合 count）
    db.flush()
    _ = meta  # meta 由 api 层直接读取，无需入库
