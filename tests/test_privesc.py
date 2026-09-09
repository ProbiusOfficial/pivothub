"""提权智能匹配（M5-2）：规则库匹配 + 规则接口 + 不可达会话的诚实失败。

真实扫描需要在靶机上执行采集命令，见 `.verify/` 与 `scripts/lab`。
"""

from __future__ import annotations

LINUX_SAMPLE = """uid=33(www-data) gid=33(www-data) groups=33(www-data),999(docker)
Linux web-dmz-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 22.04.3 LTS"
Matching Defaults entries for www-data on web-dmz-01:
    env_reset, env_keep+=LD_PRELOAD
User www-data may run the following commands on web-dmz-01:
    (root) NOPASSWD: /usr/bin/vim
/usr/bin/find
/usr/bin/pkexec
/usr/bin/python3.10 = cap_setuid+ep
/etc/cron.d/backup
/etc/passwd
"""

WINDOWS_SAMPLE = r"""desktop-7f3k\webuser

PRIVILEGES INFORMATION
----------------------
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeShutdownPrivilege           Shut down the system                        Disabled
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
"""


def test_match_linux_sample():
    from pivothub.service.privesc import match_rules, parse_facts

    facts = parse_facts(LINUX_SAMPLE, "linux")
    assert facts["kernel"] == "5.15.0-91-generic"
    assert facts["privilege"] == "www-data"
    assert facts["os"] == "Ubuntu 22.04.3 LTS"

    findings = match_rules("linux", LINUX_SAMPLE, facts)
    ids = {f["id"] for f in findings}
    for expected in ("linux-sudo-nopasswd", "linux-suid", "linux-caps",
                     "linux-pkexec-pwnkit", "linux-ld-preload", "linux-docker-group",
                     "linux-cron-writable", "linux-kernel-dirtypipe",
                     "linux-passwd-writable"):
        assert expected in ids, f"未命中: {expected}"

    suid = next(f for f in findings if f["id"] == "linux-suid")
    assert suid["evidence"] == "/usr/bin/find"  # 证据必须来自回显本身
    rels = [f["reliability"] for f in findings]
    assert rels == sorted(rels, reverse=True)

    # 可写 /etc/passwd 必须带验证步骤（否则「已执行」会被误当成提权成功）
    pw = next(f for f in findings if f["id"] == "linux-passwd-writable")
    assert pw["verify"] and pw["expect"] == "uid=0\\(root\\)"
    assert pw["cmd"].startswith("echo 'ph::0:0:root:")


def test_match_windows_sample():
    from pivothub.service.privesc import match_rules

    ids = {f["id"] for f in match_rules("windows", WINDOWS_SAMPLE)}
    assert "win-seimpersonate" in ids
    assert "win-alwaysinstallelevated" in ids


def test_kernel_rule_skipped_on_other_kernel():
    """facts.kernel 不匹配时整条规则跳过（4.4 内核不该命中 Dirty Pipe）。"""
    from pivothub.service.privesc import match_rules, parse_facts

    sample = "Linux old-box 4.4.0-210-generic x86_64 GNU/Linux\nuid=1000(tomcat)\n"
    findings = match_rules("linux", sample, parse_facts(sample, "linux"))
    ids = {f["id"] for f in findings}
    assert "linux-kernel-dirtypipe" not in ids
    assert "linux-kernel-dirtycow" in ids


def test_crlf_output_matches_anchored_rules():
    """反弹 PTY 回显是 CRLF：锚点规则（^/etc/passwd$）不能因此漏报。"""
    from pivothub.service.privesc import match_rules

    crlf = ("uid=1000(tomcat9) gid=1000(tomcat9)\r\n"
            "Linux archive-web 6.1.0-26-amd64 x86_64 GNU/Linux\r\n"
            "/usr/bin/mount\r\n/etc/passwd\r\n")
    lf = crlf.replace("\r\n", "\n")
    ids_crlf = {f["id"] for f in match_rules("linux", crlf)}
    ids_lf = {f["id"] for f in match_rules("linux", lf)}
    assert {"linux-passwd-writable", "linux-suid"} <= ids_crlf
    assert ids_crlf == ids_lf


def test_rules_endpoint(client):
    r = client.get("/api/privesc/rules")
    assert r.status_code == 200
    rules = r.json()["rules"]
    assert len(rules) >= 15
    assert {x["platform"] for x in rules} == {"linux", "windows"}
    linux = client.get("/api/privesc/rules?platform=linux").json()["rules"]
    assert linux and all(x["platform"] == "linux" for x in linux)


def test_scan_unreachable_session_reports_error(client, sandbox_project):
    """会话不可达时如实报错，不返回假结论。"""
    h = client.post("/api/hosts",
                    json={"projectId": sandbox_project, "ip": "10.99.88.77"}).json()
    s = client.post("/api/shells", json={
        "projectId": sandbox_project, "hostId": h["id"], "type": "PHP 一句话马",
        "url": "http://127.0.0.1:1/shell.php", "pass": "x", "autoCollect": False,
    }).json()
    r = client.post(f"/api/shells/{s['id']}/privesc/scan")
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["error"]


def test_apply_cmd_wrapper_quotes():
    """包装器里的 %CMD% 必须做 shell 安全引用（命令含空格/引号也不能跑偏）。"""
    from pivothub.session.base import apply_cmd_wrapper

    w = 'script -qc "su ph -c %CMD%" /dev/null'
    assert apply_cmd_wrapper("cat /flag3.txt", w) == \
        'script -qc "su ph -c \'cat /flag3.txt\'" /dev/null'
    assert apply_cmd_wrapper("id", "") == "id"
    assert apply_cmd_wrapper("id", "no-placeholder") == "id"


def test_escalation_endpoints(client, sandbox_project):
    """提权上下文：设置 / 回读 / 校验 / 取消。"""
    h = client.post("/api/hosts",
                    json={"projectId": sandbox_project, "ip": "10.99.77.66"}).json()
    s = client.post("/api/shells", json={
        "projectId": sandbox_project, "hostId": h["id"], "type": "PHP 一句话马",
        "url": "http://127.0.0.1:1/x.php", "pass": "x", "autoCollect": False,
    }).json()
    sid = s["id"]
    r = client.post(f"/api/shells/{sid}/escalation",
                    json={"user": "ph", "wrapper": 'script -qc "su ph -c %CMD%" /dev/null'})
    assert r.status_code == 200 and r.json()["escalatedUser"] == "ph"

    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert next(x for x in st["shells"] if x["id"] == sid)["escalatedUser"] == "ph"

    assert client.post(f"/api/shells/{sid}/escalation",
                       json={"user": "ph", "wrapper": "bad-no-placeholder"}).status_code == 400
    assert client.post(f"/api/shells/{sid}/escalation", json={"user": ""}).status_code == 400

    assert client.delete(f"/api/shells/{sid}/escalation").json()["escalatedUser"] == ""
