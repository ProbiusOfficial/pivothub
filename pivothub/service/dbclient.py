"""数据库客户端命令构造与结果解析（数据库面板的可视化基础）。

设计取舍：**不引入数据库驱动**，而是把客户端命令经会话层下发到目标执行
（`mysql` / `psql` / `redis-cli` / `sqlite3` / `sqlcmd`），再把回显解析成
「列 + 行」给面板渲染。这样穿透代理链路时无需在攻击机上装驱动，
也符合「命令执行只走会话层」的既有架构。

sqlite 且在本机执行时直接用 Python 内置 sqlite3 模块（零外部依赖）。
"""

from __future__ import annotations

import csv
import io
import shlex
from typing import Any

KINDS = ("mysql", "postgres", "sqlite", "redis", "mssql")

#: 默认端口（0 表示用客户端默认值）
DEFAULT_PORTS = {"mysql": 3306, "postgres": 5432, "redis": 6379, "mssql": 1433, "sqlite": 0}


def _q(text: str) -> str:
    """POSIX 单引号安全引用（目标多为 Linux；Windows 目标请用无特殊字符的 SQL）。"""
    return shlex.quote(str(text or ""))


def build_command(kind: str, host: str, port: int, username: str, password: str,
                  db_name: str, sql: str) -> str:
    """按数据库类型拼客户端命令（2>&1 让错误也回到回显里）。"""
    kind = (kind or "mysql").lower()
    host = host or "127.0.0.1"
    port = int(port or DEFAULT_PORTS.get(kind, 0) or 0)
    if kind == "mysql":
        pw = f" -p{_q(password)}" if password else ""
        port_arg = f" -P {port}" if port else ""
        return (f"mysql -h {_q(host)}{port_arg} -u {_q(username or 'root')}{pw}"
                f" -B -e {_q(sql)} 2>&1")
    if kind == "postgres":
        db = db_name or "postgres"
        port_arg = f" -p {port}" if port else ""
        return (f"PGPASSWORD={_q(password)} psql -h {_q(host)}{port_arg} "
                f"-U {_q(username or 'postgres')} -d {_q(db)} --csv -c {_q(sql)} 2>&1")
    if kind == "redis":
        auth = f" -a {_q(password)}" if password else ""
        port_arg = f" -p {port}" if port else ""
        return f"redis-cli -h {_q(host)}{port_arg}{auth} --no-raw {_q(sql)} 2>&1"
    if kind == "sqlite":
        # host 即 .db 文件路径
        return f"sqlite3 -header -csv {_q(host)} {_q(sql)} 2>&1"
    if kind == "mssql":
        port_arg = f",{port}" if port else ""
        return (f"sqlcmd -S {_q(host)}{port_arg} -U {_q(username or 'sa')} "
                f"-P {_q(password)} -W -s \"|\" -Q {_q(sql)} 2>&1")
    raise ValueError(f"不支持的数据库类型: {kind}")


def _split_tsv(text: str) -> tuple[list[str], list[list[str]]]:
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
    if not lines:
        return [], []
    cols = lines[0].split("\t")
    rows = [ln.split("\t") for ln in lines[1:]]
    return cols, rows


def _split_csv(text: str) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(text.replace("\r\n", "\n")))
    rows = [r for r in reader if any(str(c).strip() for c in r)]
    if not rows:
        return [], []
    return rows[0], rows[1:]


def _split_pipe(text: str) -> tuple[list[str], list[list[str]]]:
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
    if not lines:
        return [], []
    return [c.strip() for c in lines[0].split("|")], [
        [c.strip() for c in ln.split("|")] for ln in lines[1:]]


#: 经 WebShell 通道取回中文时的编码加固：目标侧 base64 成纯 ASCII 再回传，
#: 避免管道 / PTY 的 locale 把 UTF-8 中文替换成 `?`（tr 兼容 busybox）。
B64_SUFFIX = " 2>&1 | base64 | tr -d '\\r\\n'"


def wrap_b64(cmd: str) -> str:
    """把命令包成 base64 回传形式（去掉原有的 2>&1，避免重复重定向）。"""
    base = cmd[:-5] if cmd.endswith(" 2>&1") else cmd
    return base + B64_SUFFIX


def try_decode_b64(output: str) -> str | None:
    """从回显里取出 base64 段并解码；不像 base64（目标没有 base64 命令）时返回 None。"""
    import base64 as _b64
    import re as _re

    runs = _re.findall(r"[A-Za-z0-9+/=]{8,}", output or "")
    if not runs:
        return None
    text = max(runs, key=len)
    try:
        raw = _b64.b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


#: 常见客户端错误前缀（命中即视为失败，把原文交给用户）
_ERROR_HINTS = (
    "ERROR", "error:", "FATAL", "Access denied", "Unknown database", "no such table",
    "command not found", "not found", "无法", "拒绝访问", "不是内部或外部命令",
    "Can't connect", "Connection refused", "NOAUTH", "WRONGPASS",
)


def parse_result(kind: str, output: str) -> dict[str, Any]:
    """把客户端回显解析为 {columns, rows, error}；识别错误前缀。"""
    text = (output or "").strip()
    if not text:
        return {"columns": [], "rows": [], "error": ""}
    for hint in _ERROR_HINTS:
        if hint in text:
            return {"columns": [], "rows": [], "error": text[:500]}
    kind = (kind or "mysql").lower()
    if kind == "mysql":
        cols, rows = _split_tsv(text)
    elif kind in ("postgres", "sqlite"):
        cols, rows = _split_csv(text)
    elif kind == "mssql":
        cols, rows = _split_pipe(text)
    else:  # redis：非表格，单列返回
        cols, rows = ["result"], [[ln] for ln in text.split("\n") if ln.strip()]
    return {"columns": cols, "rows": rows, "error": ""}


def run_sqlite_local(path: str, sql: str) -> dict[str, Any]:
    """本机 sqlite：直接用 Python 内置模块（不依赖 sqlite3 CLI）。"""
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as e:
        return {"columns": [], "rows": [], "error": f"打开数据库失败: {e}"}
    try:
        cur = con.execute(sql)
        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = [["" if v is None else str(v) for v in r] for r in cur.fetchall()]
        else:
            con.commit()
            cols, rows = ["affected"], [[str(cur.rowcount)]]
        return {"columns": cols, "rows": rows, "error": ""}
    except sqlite3.Error as e:
        return {"columns": [], "rows": [], "error": str(e)}
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 结构探测（数据库面板的「自动探测 + 结构树」）
# ---------------------------------------------------------------------------

#: 各类数据库统一列顺序的结构查询：db / table / column / type / nullable / key / rows
SCHEMA_SQL = {
    "mysql": (
        "SELECT c.table_schema AS db, c.table_name AS tbl, c.column_name AS col, "
        "c.column_type AS typ, c.is_nullable AS nullable, c.column_key AS ckey, "
        "COALESCE(t.table_rows, 0) AS rows "
        "FROM information_schema.columns c "
        "LEFT JOIN information_schema.tables t "
        "ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
        "WHERE c.table_schema NOT IN "
        "('mysql','information_schema','performance_schema','sys') "
        "ORDER BY c.table_schema, c.table_name, c.ordinal_position"
    ),
    "postgres": (
        "SELECT c.table_schema AS db, c.table_name AS tbl, c.column_name AS col, "
        "c.data_type AS typ, c.is_nullable AS nullable, '' AS ckey, 0 AS rows "
        "FROM information_schema.columns c "
        "WHERE c.table_schema NOT IN ('pg_catalog','information_schema') "
        "ORDER BY c.table_schema, c.table_name, c.ordinal_position"
    ),
    "mssql": (
        "SELECT c.TABLE_SCHEMA AS db, c.TABLE_NAME AS tbl, c.COLUMN_NAME AS col, "
        "c.DATA_TYPE AS typ, c.IS_NULLABLE AS nullable, '' AS ckey, 0 AS rows "
        "FROM INFORMATION_SCHEMA.COLUMNS c "
        "ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION"
    ),
    "redis": "KEYS *",
}


def build_schema_from_rows(kind: str, rows: list[list[str]]) -> list[dict]:
    """把统一列顺序的结构查询结果整理成「库 → 表 → 列」树。"""
    kind = (kind or "mysql").lower()
    if kind == "redis":
        keys = [r[0] for r in rows if r and r[0]]
        return [{"name": "db0", "tables": [{"name": k, "rows": 0, "columns": []} for k in keys]}]

    dbs: dict[str, dict] = {}
    for r in rows:
        if len(r) < 5:
            continue
        db, tbl, col, typ = (r[0] or ""), (r[1] or ""), (r[2] or ""), (r[3] or "")
        nullable = str(r[4] or "").upper() in ("YES", "TRUE", "1")
        key = (r[5] if len(r) > 5 else "") or ""
        try:
            row_count = int(float(r[6])) if len(r) > 6 and r[6] not in (None, "") else 0
        except (TypeError, ValueError):
            row_count = 0
        if not db or not tbl:
            continue
        db_node = dbs.setdefault(db, {"name": db, "tables": {}})
        tbl_node = db_node["tables"].setdefault(tbl, {"name": tbl, "rows": row_count, "columns": []})
        if row_count:
            tbl_node["rows"] = max(tbl_node["rows"], row_count)
        if col:
            tbl_node["columns"].append({"name": col, "type": typ, "nullable": nullable, "key": key})
    out = []
    for db in sorted(dbs.values(), key=lambda x: x["name"]):
        tables = sorted(db["tables"].values(), key=lambda x: x["name"])
        out.append({"name": db["name"], "tables": tables})
    return out


def run_sqlite_schema_local(path: str) -> list[dict]:
    """本机 sqlite 结构：sqlite_master + PRAGMA table_info + 每表行数。"""
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
        out_tables = []
        for t in tables:
            try:
                count = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            except sqlite3.Error:
                count = 0
            cols = []
            for cid, name, ctype, notnull, dflt, pk in con.execute(f'PRAGMA table_info("{t}")').fetchall():
                cols.append({"name": name, "type": ctype or "", "nullable": not bool(notnull),
                             "key": "PRI" if pk else ""})
            out_tables.append({"name": t, "rows": int(count or 0), "columns": cols})
        return [{"name": "main", "tables": out_tables}]
    finally:
        con.close()
