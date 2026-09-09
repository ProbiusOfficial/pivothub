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
