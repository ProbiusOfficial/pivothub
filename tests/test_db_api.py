"""数据库连接面板：连接 CRUD + 本机 sqlite 查询 + 客户端命令/解析。"""

from __future__ import annotations

import sqlite3


def test_db_connection_crud(client, sandbox_project):
    r = client.post("/api/db/connections", json={
        "projectId": sandbox_project, "name": "本地测试库", "kind": "sqlite",
        "host": "/tmp/x.db", "note": "pytest",
    })
    assert r.status_code == 200
    cid = r.json()["id"]
    assert r.json()["name"] == "本地测试库"

    listed = client.get(f"/api/db/connections?projectId={sandbox_project}").json()
    assert any(c["id"] == cid for c in listed["connections"])
    assert "mysql" in listed["kinds"] and listed["defaultPorts"]["mysql"] == 3306

    assert client.delete(f"/api/db/connections/{cid}").json()["deleted"] == cid
    assert all(c["id"] != cid for c in
               client.get(f"/api/db/connections?projectId={sandbox_project}").json()["connections"])


def test_db_connection_bad_kind(client, sandbox_project):
    r = client.post("/api/db/connections",
                    json={"projectId": sandbox_project, "kind": "oracle", "host": "x"})
    assert r.status_code == 400


def test_sqlite_query_local(client, sandbox_project, tmp_path):
    """本机 sqlite 走 Python 内置模块：真实建库、真实查询。"""
    db_file = tmp_path / "demo.db"
    con = sqlite3.connect(db_file)
    con.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    con.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    con.commit()
    con.close()

    cid = client.post("/api/db/connections", json={
        "projectId": sandbox_project, "name": "pytest sqlite", "kind": "sqlite",
        "host": str(db_file),
    }).json()["id"]

    r = client.post(f"/api/db/connections/{cid}/query",
                    json={"sql": "SELECT id, name FROM users ORDER BY id"}).json()
    assert r["ok"] is True
    assert r["columns"] == ["id", "name"]
    assert r["rows"] == [["1", "alice"], ["2", "bob"]]

    tables = client.get(f"/api/db/connections/{cid}/tables").json()
    assert tables["ok"] is True
    assert ["users"] in tables["rows"]

    bad = client.post(f"/api/db/connections/{cid}/query",
                      json={"sql": "SELECT * FROM nope"}).json()
    assert bad["ok"] is False and bad["error"]

    client.delete(f"/api/db/connections/{cid}")


def test_build_command_and_parse():
    from pivothub.service import dbclient

    cmd = dbclient.build_command("mysql", "10.0.0.5", 3307, "root", "p@ss w", "app", "SHOW DATABASES")
    assert cmd.startswith("mysql -h 10.0.0.5 -P 3307 -u root")
    assert "-p'p@ss w'" in cmd and cmd.endswith("2>&1")

    out = "Database\napp\nmysql\n"
    parsed = dbclient.parse_result("mysql", out)
    assert parsed["columns"] == ["Database"]
    assert parsed["rows"] == [["app"], ["mysql"]]

    err = dbclient.parse_result("mysql", "ERROR 1045 (28000): Access denied for user 'root'")
    assert err["error"] and not err["rows"]

    csv_out = "id,name\n1,alice\n2,bob\n"
    parsed = dbclient.parse_result("postgres", csv_out)
    assert parsed["columns"] == ["id", "name"] and len(parsed["rows"]) == 2

    redis_out = "1) \"a\"\n2) \"b\""
    parsed = dbclient.parse_result("redis", redis_out)
    assert parsed["columns"] == ["result"] and len(parsed["rows"]) == 2
