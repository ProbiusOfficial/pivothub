"""应用指纹探测 / 目录上下文发现：单测 + API 冒烟（fake session 控制回显）。

fake session 实现 exec(cmd, timeout) 返回可控 ExecResult，覆盖：
  - Shiro rememberMe=deleteMe → 识别为 shiro
  - Jenkins /api/json 200 → 识别为 jenkins
  - 全部 404 → app == ""（不得硬猜）
  - discover_dirs 命中 /app 200 → note 含「非 ROOT context」提示
"""

from __future__ import annotations

import base64

import pytest

from pivothub.service import fingerprint as FP


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


class FakeSession:
    """控制回显的假会话：exec 返回预设 output，test 恒 ok。"""

    def __init__(self, output: str = "", platform: str = "linux"):
        self._output = output
        self.platform = platform
        self.calls: list[str] = []

    def exec(self, cmd, timeout: float = 12.0):
        self.calls.append(cmd)

        class R:  # 模拟 ExecResult
            pass

        r = R()
        r.output = self._output
        r.error = ""
        r.ok = True
        r.ms = 10
        r.timed_out = False
        return r

    def test(self):
        class R:
            pass

        r = R()
        r.ok = True
        r.error = ""
        r.ms = 1
        return r


def fp_line(tag: str, code: int, srv: str = "", setc: str = "", body: str = "") -> str:
    return "FP\t%s\t%d\t%s\t%s\t%s" % (tag, code, b64(srv), b64(setc), b64(body))


# Shiro：根路径 200，且带 rememberMe=1 的响应暴露 rememberMe=deleteMe
OUT_SHIRO = "\n".join([
    fp_line("BASE", 200, srv="Server: Apache-Coyote/1.1", body="<html>Apache Tomcat</html>"),
    fp_line("SHIRO", 200, setc="Set-Cookie: rememberMe=deleteMe; Path=/; HttpOnly",
            body="<html>login</html>"),
    fp_line("JENKINS", 404, body=""),
    fp_line("NACOS", 404, body=""),
    fp_line("REG", 404, body=""),
    fp_line("ACT", 404, body=""),
])

# Jenkins：/api/json 匿名可读
OUT_JENKINS = "\n".join([
    fp_line("BASE", 200, body="<html>Jenkins</html>"),
    fp_line("SHIRO", 404, body=""),
    fp_line("JENKINS", 200, body='{"nodeName":"master","mode":"NORMAL","useSecurity":false}'),
    fp_line("NACOS", 404, body=""),
    fp_line("REG", 404, body=""),
    fp_line("ACT", 404, body=""),
])

# 全部 404：必须如实标 unknown，不得硬猜
OUT_ALL_404 = "\n".join([
    fp_line("BASE", 404, body=""),
    fp_line("SHIRO", 404, body=""),
    fp_line("JENKINS", 404, body=""),
    fp_line("NACOS", 404, body=""),
    fp_line("REG", 404, body=""),
    fp_line("ACT", 404, body=""),
])

# 目录发现：/app 返回 200
OUT_DIR_APP = "DIR\t200\t1234\t%s\t/app" % b64("App Console")


def test_scan_shiro_identified():
    s = FakeSession(OUT_SHIRO)
    r = FP.scan_apps(s, ["http://172.31.0.20:8080"])
    items = r["items"]
    assert len(items) == 1
    it = items[0]
    assert it["app"] == "Shiro"
    assert any("kPH+bIxk5D2deZiIxcaaaA==" in a for a in it["advice"])
    assert it["status"] == 200
    shiro_probe = next(p for p in it["probes"] if p["name"] == "shiro")
    assert shiro_probe["state"] == "ok"


def test_scan_jenkins_identified():
    s = FakeSession(OUT_JENKINS)
    r = FP.scan_apps(s, ["http://10.0.0.5:8080"])
    it = r["items"][0]
    assert it["app"] == "Jenkins"
    assert any("/script" in a or "Script Console" in a for a in it["advice"])


def test_scan_all_404_is_unknown_not_guessed():
    s = FakeSession(OUT_ALL_404)
    r = FP.scan_apps(s, ["http://10.0.0.9:80"])
    it = r["items"][0]
    assert it["app"] == ""                       # 不得硬猜
    assert it["status"] == 404
    # 没有任何探针被误判为 ok
    assert all(p["state"] != "ok" for p in it["probes"])
    assert r["summary"]["identified"] == 0
    assert r["summary"]["unknown"] == 1


def test_scan_invalid_target_is_honest():
    s = FakeSession("")
    r = FP.scan_apps(s, ["not-a-url"])
    it = r["items"][0]
    assert it["app"] == ""
    assert "非法" in it["evidence"]


def test_discover_dirs_non_root_context_note():
    s = FakeSession(OUT_DIR_APP)
    r = FP.discover_dirs(s, ["http://172.31.0.20:8080"])
    items = r["items"]
    app_item = next(i for i in items if i["url"].endswith("/app"))
    assert app_item["status"] == 200
    assert "非 ROOT" in app_item["note"]        # 重点：覆盖靶场漏测的根因
    assert r["summary"]["total"] == len(items)
    assert r["summary"]["hits"] >= 1


def test_discover_dirs_backup_and_actuator_notes():
    out = "\n".join([
        "DIR\t200\t500\t%s\t/WEB-INF/web.xml" % b64("x"),
        "DIR\t200\t200\t%s\t/actuator/env" % b64("{}"),
        "DIR\t404\t0\t\t/manager/html",
    ])
    s = FakeSession(out)
    r = FP.discover_dirs(s, ["http://x:8080"])
    by_path = {i["url"].split("//", 1)[-1].split("/", 1)[-1]: i for i in r["items"]}
    assert "源码" in by_path["WEB-INF/web.xml"]["note"]
    assert "Actuator" in by_path["actuator/env"]["note"]
    assert "Tomcat" in by_path["manager/html"]["note"]


def test_scan_python_engine_syntax_valid():
    """回退用的 python3 脚本必须语法合法（解码 base64 后 compile 通过）。"""
    import ast

    for base in ("http://172.31.0.20:8080", "https://example.com/a%20b"):
        cmd = FP._py_scan_cmd(base)
        b = cmd.rsplit(" ", 1)[-1]              # 末尾的 base64
        src = base64.b64decode(b).decode("utf-8")
        ast.parse(src)                          # 不应抛 SyntaxError
        assert "BASE = '''" in src

    cmd = FP._py_dir_cmd("http://x/", ["/app", "/.git/HEAD"])
    b = cmd.rsplit(" ", 1)[-1]
    ast.parse(base64.b64decode(b).decode("utf-8"))


# ---------------------------------------------------------------------------
# API 冒烟：把 router 挂到 api_router 下（真实接线由用户统一在 api/__init__.py 完成）。
# 必须挂进 api_router——app 已在 api_router 之后挂载了根 Mount("/")，直接挂 app 会被
# 静态 Mount 抢先匹配而返回 405。
# ---------------------------------------------------------------------------

from pivothub.api import api_router  # noqa: E402
from pivothub.api.fingerprint import router as _fp_router  # noqa: E402

if not any(getattr(rt, "path", "").endswith("/fingerprint/scan")
           for rt in api_router.routes):
    api_router.include_router(_fp_router)


def test_fingerprint_scan_api_smoke(client, monkeypatch):
    fake = FakeSession(OUT_SHIRO, platform="linux")
    # 复用 shells 取会话逻辑，替换为假会话（避免真实 SSH/HTTP 连接）
    monkeypatch.setattr("pivothub.api.shells._open_session", lambda db, s: fake)
    monkeypatch.setattr("pivothub.api.fingerprint._open_session", lambda db, s: fake)

    r = client.post("/api/hosts", json={
        "ip": "10.0.0.99", "hostname": "fplab", "os": "Linux", "layer": "L1", "note": "fp"})
    assert r.status_code == 200
    host_id = r.json()["id"]
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "SSH", "url": "ssh://10.0.0.99",
        "pass": "x", "encoder": "none", "autoCollect": False})
    assert r.status_code == 200
    shell_id = r.json()["id"]

    r = client.post("/api/fingerprint/scan", json={
        "shellId": shell_id, "targets": ["http://172.31.0.20:8080"]})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "items" in body and len(body["items"]) >= 1
    assert body["items"][0]["app"] == "Shiro"
    assert len(fake.calls) >= 1


def test_fingerprint_dirs_api_smoke(client, monkeypatch):
    fake = FakeSession(OUT_DIR_APP, platform="linux")
    monkeypatch.setattr("pivothub.api.shells._open_session", lambda db, s: fake)
    monkeypatch.setattr("pivothub.api.fingerprint._open_session", lambda db, s: fake)

    r = client.post("/api/hosts", json={
        "ip": "10.0.0.98", "hostname": "fplab2", "os": "Linux", "layer": "L1", "note": "fp"})
    host_id = r.json()["id"]
    r = client.post("/api/shells", json={
        "hostId": host_id, "type": "SSH", "url": "ssh://10.0.0.98",
        "pass": "x", "encoder": "none", "autoCollect": False})
    shell_id = r.json()["id"]

    r = client.post("/api/fingerprint/dirs", json={
        "shellId": shell_id, "baseUrls": ["http://172.31.0.20:8080"]})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert any(i["url"].endswith("/app") and "非 ROOT" in i["note"] for i in body["items"])
