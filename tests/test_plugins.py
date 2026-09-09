"""插件市场：清单 / 安装 / 启停 / 卸载，以及安装后的数据贡献是否生效。

注意：conftest 把 PIVOTHUB_DATA_DIR 指向仓库 data/ 目录，安装会真实落盘，
因此每个用例都用 try/finally 卸载，避免污染工作区。
"""

from __future__ import annotations


def test_plugin_registry_listed(client):
    r = client.get("/api/plugins")
    assert r.status_code == 200
    data = r.json()
    ids = {p["id"] for p in data["items"]}
    assert {"linux-privesc-extra", "privesc-rules-extra", "tty-fixes-extra"} <= ids
    assert data["allowedDirs"] == ["commands", "payloads", "tty_fixes", "privesc"]
    # 不断言「未安装」：data/plugins 与真实面板共用，用户可能已经装了插件
    for p in data["items"]:
        if p["id"] in ids:
            assert p["installable"] is True


def _plugin_state(client, pid):
    for p in client.get("/api/plugins").json()["items"]:
        if p["id"] == pid:
            return bool(p["installed"]), bool(p["enabled"])
    return False, False


def test_plugin_install_toggle_uninstall_affects_state(client):
    """安装后命令库出现插件命令，停用/卸载后消失（真实影响 /state）。"""
    pid = "linux-privesc-extra"
    was_installed, was_enabled = _plugin_state(client, pid)
    try:
        r = client.post(f"/api/plugins/{pid}/install")
        assert r.status_code == 200 and r.json()["ok"] is True

        listed = {p["id"]: p for p in client.get("/api/plugins").json()["items"]}
        assert listed[pid]["installed"] and listed[pid]["enabled"]

        st = client.get("/api/projects/proj-1/state").json()
        cmd_ids = {c["id"] for c in st["commands"]}
        assert "pl-linux-suid" in cmd_ids

        # 停用 → 贡献消失
        assert client.post(f"/api/plugins/{pid}/toggle", json={"enabled": False}).json()["enabled"] is False
        st = client.get("/api/projects/proj-1/state").json()
        assert "pl-linux-suid" not in {c["id"] for c in st["commands"]}

        # 重新启用 → 回来
        client.post(f"/api/plugins/{pid}/toggle", json={"enabled": True})
        st = client.get("/api/projects/proj-1/state").json()
        assert "pl-linux-suid" in {c["id"] for c in st["commands"]}
    finally:
        # 恢复用例开始前的状态（用户面板可能本来就装了该插件）
        if was_installed:
            client.post(f"/api/plugins/{pid}/install")
            if not was_enabled:
                client.post(f"/api/plugins/{pid}/toggle", json={"enabled": False})
        else:
            client.delete(f"/api/plugins/{pid}")

    if not was_installed:
        listed = {p["id"]: p for p in client.get("/api/plugins").json()["items"]}
        assert listed[pid]["installed"] is False


def test_plugin_privesc_rules_contribute(client):
    pid = "privesc-rules-extra"
    was_installed, was_enabled = _plugin_state(client, pid)
    try:
        assert client.post(f"/api/plugins/{pid}/install").json()["ok"] is True
        rules = client.get("/api/privesc/rules?platform=linux").json()["rules"]
        assert "pl-linux-nfs-no-root-squash" in {r["id"] for r in rules}
    finally:
        if was_installed:
            client.post(f"/api/plugins/{pid}/install")
            if not was_enabled:
                client.post(f"/api/plugins/{pid}/toggle", json={"enabled": False})
        else:
            client.delete(f"/api/plugins/{pid}")
    if not was_installed:
        rules = client.get("/api/privesc/rules?platform=linux").json()["rules"]
        assert "pl-linux-nfs-no-root-squash" not in {r["id"] for r in rules}


def test_plugin_install_unknown_and_bad_id(client):
    assert client.post("/api/plugins/not-in-registry/install").status_code == 404
    assert client.delete("/api/plugins/not-in-registry").status_code == 404
