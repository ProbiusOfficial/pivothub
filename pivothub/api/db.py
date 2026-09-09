"""数据库连接面板 API：连接管理 + 测试 + 查询（经会话层执行客户端命令）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from ..config import DEFAULT_PROJECT_ID
from ..db import get_db, now
from ..models import DbConnection
from ..schemas.common import rid
from ..service import add_event
from ..service import dbclient
from ..session import SessionError
from .deps import get_project

router = APIRouter()


class DbConnIn(BaseModel):
    projectId: str = ""
    name: str = ""
    kind: str = "mysql"
    host: str = "127.0.0.1"
    port: int = 0
    username: str = ""
    password: str = ""
    dbName: str = ""
    shellId: str = ""
    note: str = ""


class DbQueryIn(BaseModel):
    sql: str


def _out(c: DbConnection) -> dict:
    return {
        "id": c.id, "name": c.name, "kind": c.kind, "host": c.host, "port": c.port,
        "username": c.username, "password": c.password, "dbName": c.db_name,
        "shellId": c.shell_id, "note": c.note, "createdAt": c.created_at,
        "defaultPort": dbclient.DEFAULT_PORTS.get(c.kind, 0),
    }


def _get(db: DBSession, conn_id: str) -> DbConnection:
    c = db.get(DbConnection, conn_id)
    if c is None:
        raise HTTPException(404, "数据库连接不存在")
    return c


@router.get("/db/connections")
def db_list(projectId: str = "", db: DBSession = Depends(get_db)):
    project = get_project(db, projectId or DEFAULT_PROJECT_ID)
    rows = (db.query(DbConnection)
            .filter(DbConnection.project_id == project.id)
            .order_by(DbConnection.created_at, DbConnection.id).all())
    return {"connections": [_out(c) for c in rows], "kinds": list(dbclient.KINDS),
            "defaultPorts": dbclient.DEFAULT_PORTS}


@router.post("/db/connections")
def db_create(form: DbConnIn, db: DBSession = Depends(get_db)):
    project = get_project(db, form.projectId or DEFAULT_PROJECT_ID)
    kind = (form.kind or "mysql").lower()
    if kind not in dbclient.KINDS:
        raise HTTPException(400, f"不支持的数据库类型: {form.kind}")
    name = (form.name or "").strip() or f"{kind}@{form.host}"
    c = DbConnection(
        id=rid("db"), project_id=project.id, name=name, kind=kind,
        host=(form.host or "127.0.0.1").strip(), port=int(form.port or 0),
        username=form.username, password=form.password, db_name=form.dbName,
        shell_id=form.shellId, note=form.note, created_at=now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    db.add(c)
    add_event(db, project.id, "note", f"登记数据库连接：{name}",
              detail=f"{kind}://{c.username}@{c.host}:{c.port or dbclient.DEFAULT_PORTS.get(kind, 0)}"
                     f"{' · 经会话 ' + c.shell_id if c.shell_id else ' · 本机执行'}")
    db.commit()
    return _out(c)


@router.delete("/db/connections/{conn_id}")
def db_delete(conn_id: str, db: DBSession = Depends(get_db)):
    c = _get(db, conn_id)
    db.delete(c)
    db.commit()
    return {"deleted": conn_id}


def _exec_via_session(db: DBSession, c: DbConnection, sql: str, timeout: float = 60.0) -> dict:
    """经会话执行客户端命令：优先 base64 回传（中文不乱码），目标无 base64 时退回明文。"""
    from .shells import _get_shell, _open_session

    s = _get_shell(db, c.shell_id)
    try:
        sess = _open_session(db, s)
    except SessionError as e:
        return {"columns": [], "rows": [], "error": str(e), "cmd": "", "ms": 0}
    cmd = dbclient.build_command(c.kind, c.host, c.port, c.username, c.password,
                                 c.db_name, sql)
    r = sess.exec(dbclient.wrap_b64(cmd), timeout=timeout)
    text = dbclient.try_decode_b64(r.output)
    if text is None:  # 目标没有 base64（或输出不是 base64）：退回明文
        r = sess.exec(cmd, timeout=timeout)
        text = r.output
    parsed = dbclient.parse_result(c.kind, text)
    if not parsed["error"] and r.error and not r.ok and not parsed["rows"]:
        parsed["error"] = r.error
    return {**parsed, "cmd": cmd, "ms": r.ms}


def _exec(db: DBSession, c: DbConnection, sql: str) -> dict:
    """执行 SQL：sqlite + 本机 → Python 内置；其余经会话层客户端命令。"""
    if c.kind == "sqlite" and not c.shell_id:
        res = dbclient.run_sqlite_local(c.host, sql)
        return {**res, "cmd": f"sqlite3 {c.host} {sql!r}", "ms": 0}
    if not c.shell_id:
        return {"columns": [], "rows": [], "error": "该类型需要指定一个会话（或改用 sqlite 本机路径）",
                "cmd": "", "ms": 0}
    return _exec_via_session(db, c, sql)


@router.post("/db/connections/{conn_id}/test")
def db_test(conn_id: str, db: DBSession = Depends(get_db)):
    """连通性测试：跑一条最小查询，返回真实回显。"""
    c = _get(db, conn_id)
    probe = {"mysql": "SELECT VERSION()", "postgres": "SELECT version()",
             "sqlite": "SELECT sqlite_version()", "redis": "PING",
             "mssql": "SELECT @@VERSION"}.get(c.kind, "SELECT 1")
    out = _exec(db, c, probe)
    ok = not out["error"]
    return {"ok": ok, "probe": probe, **out}


@router.post("/db/connections/{conn_id}/query")
def db_query(conn_id: str, form: DbQueryIn, db: DBSession = Depends(get_db)):
    """执行 SQL 并返回列/行（面板表格渲染）。"""
    c = _get(db, conn_id)
    sql = (form.sql or "").strip()
    if not sql:
        raise HTTPException(400, "SQL 不能为空")
    out = _exec(db, c, sql)
    if out["error"]:
        return JSONResponse({"ok": False, **out})
    return {"ok": True, **out}


@router.get("/db/connections/{conn_id}/schema")
def db_schema(conn_id: str, db: DBSession = Depends(get_db)):
    """自动探测数据库结构：库 → 表 → 列（类型 / 可空 / 主键 / 行数估计）。"""
    c = _get(db, conn_id)
    if c.kind == "sqlite" and not c.shell_id:
        tree = dbclient.run_sqlite_schema_local(c.host)
        return {"ok": True, "kind": c.kind, "databases": tree, "ms": 0,
                "sql": "sqlite_master + PRAGMA table_info"}
    if not c.shell_id:
        return JSONResponse({"ok": False, "kind": c.kind, "databases": [],
                             "error": "该类型需要指定一个会话（或改用 sqlite 本机路径）"})

    if c.kind == "sqlite":  # 远程 sqlite：先列表，再逐表 PRAGMA
        sql0 = ("SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")
        parsed = _exec_via_session(db, c, sql0, timeout=30)
        if parsed["error"]:
            return JSONResponse({"ok": False, "kind": c.kind, "databases": [],
                                 "error": parsed["error"]})
        tables = []
        for row in parsed["rows"]:
            tname = (row[0] if row else "").strip()
            if not tname:
                continue
            p2 = _exec_via_session(db, c, f'PRAGMA table_info("{tname}")', timeout=30)
            cols = []
            for c2 in p2["rows"]:  # cid|name|type|notnull|dflt|pk
                if len(c2) >= 6:
                    cols.append({"name": c2[1], "type": c2[2],
                                 "nullable": c2[3] in ("0", ""),
                                 "key": "PRI" if c2[5] not in ("0", "") else ""})
            tables.append({"name": tname, "rows": 0, "columns": cols})
        return {"ok": True, "kind": c.kind, "databases": [{"name": "main", "tables": tables}],
                "ms": parsed.get("ms", 0), "sql": "sqlite_master + PRAGMA table_info"}

    sql = dbclient.SCHEMA_SQL.get(c.kind)
    if not sql:
        return JSONResponse({"ok": False, "kind": c.kind, "databases": [],
                             "error": f"暂不支持探测 {c.kind} 结构"})
    parsed = _exec_via_session(db, c, sql, timeout=45)
    if parsed["error"]:
        return JSONResponse({"ok": False, "kind": c.kind, "databases": [],
                             "error": parsed["error"], "cmd": parsed.get("cmd", "")})
    return {"ok": True, "kind": c.kind,
            "databases": dbclient.build_schema_from_rows(c.kind, parsed["rows"]),
            "ms": parsed.get("ms", 0), "sql": sql}


@router.get("/db/connections/{conn_id}/tables")
def db_tables(conn_id: str, db: DBSession = Depends(get_db)):
    """列出库/表（按类型走信息模式查询）。"""
    c = _get(db, conn_id)
    if c.kind == "mysql":
        sql = ("SELECT table_schema AS db_name, table_name, table_rows "
               "FROM information_schema.tables "
               "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') "
               "ORDER BY table_schema, table_name")
    elif c.kind == "postgres":
        sql = ("SELECT table_schema AS db_name, table_name, 0 AS table_rows "
               "FROM information_schema.tables "
               "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
               "ORDER BY table_schema, table_name")
    elif c.kind == "sqlite":
        sql = "SELECT name AS table_name FROM sqlite_master WHERE type='table' ORDER BY name"
    elif c.kind == "mssql":
        sql = ("SELECT TABLE_SCHEMA AS db_name, TABLE_NAME AS table_name, 0 AS table_rows "
               "FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_SCHEMA, TABLE_NAME")
    else:
        sql = "KEYS *"
    out = _exec(db, c, sql)
    return {"ok": not out["error"], "sql": sql, **out}
