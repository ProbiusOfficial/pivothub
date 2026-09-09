"""移除资产：级联清理会话 / 链路 / 凭据 / Flag；本机节点与不存在的主机如实报错。"""

from __future__ import annotations


def _new_host(client, project_id: str, ip: str) -> str:
    r = client.post("/api/hosts", json={
        "projectId": project_id, "ip": ip, "hostname": "rm-lab", "os": "Linux",
        "layer": "L1", "segment": "10.99.0.0/24"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_remove_host_cascades(client, sandbox_project):
    host_id = _new_host(client, sandbox_project, "10.99.0.10")

    r = client.post("/api/shells", json={
        "projectId": sandbox_project, "hostId": host_id, "type": "PHP 一句话马",
        "url": "http://127.0.0.1:1/shell.php", "pass": "x", "encoder": "none",
        "autoCollect": False})
    assert r.status_code == 200, r.text
    shell_id = r.json()["id"]

    r = client.post("/api/creds", json={
        "projectId": sandbox_project, "hostId": host_id, "username": "root",
        "secret": "toor", "kind": "密码", "services": "22"})
    assert r.status_code == 200, r.text
    cred_id = r.json()["id"]

    r = client.post("/api/flags", json={
        "projectId": sandbox_project, "hostId": host_id,
        "stage": "L1 入口", "value": "flag{rm}"})
    assert r.status_code == 200, r.text
    flag_id = r.json()["id"]

    r = client.post("/api/timeline/events", json={
        "projectId": sandbox_project, "kind": "note", "title": "移除前的手记",
        "hostId": host_id})
    assert r.status_code == 200, r.text
    event_id = r.json()["id"]

    r = client.delete(f"/api/hosts/{host_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted"] == host_id and body["ip"] == "10.99.0.10"
    assert body["shells"] == 1 and body["creds"] == 1 and body["flags"] == 1

    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert all(h["id"] != host_id for h in st["hosts"])
    assert all(s["id"] != shell_id for s in st["shells"])
    assert all(c["id"] != cred_id for c in st["creds"])
    assert all(f["id"] != flag_id for f in st["flags"])
    # 历史事件保留，仅解绑主机
    ev = next(e for e in st["timeline"] if e["id"] == event_id)
    assert ev["title"] == "移除前的手记" and not ev["hostId"]
    assert any("移除资产" in e["title"] for e in st["timeline"])


def test_remove_local_host_rejected(client, sandbox_project):
    st = client.get(f"/api/projects/{sandbox_project}/state").json()
    local = next(h for h in st["hosts"] if h.get("isLocal"))
    r = client.delete(f"/api/hosts/{local['id']}")
    assert r.status_code == 400
    assert "本机" in r.json()["detail"]
    st2 = client.get(f"/api/projects/{sandbox_project}/state").json()
    assert any(h["id"] == local["id"] for h in st2["hosts"])


def test_remove_missing_host_404(client):
    assert client.delete("/api/hosts/h-not-exist").status_code == 404
