"""导出三格式快照测试：MD 结构、JSON 明文、HTML 包裹。"""

from __future__ import annotations


def test_export_md_snapshot(client, project_id):
    r = client.get("/api/export", params={"format": "md", "projectId": project_id})
    assert r.status_code == 200
    md = r.text
    assert md.startswith("# 2026 春秋云镜 · 三层内网 · Writeup")
    for section in ["## 0. 概览", "## 1. 网络拓扑", "## 2. 跳板链参数",
                    "## 3. 操作时间线", "## 4. 凭据清单（明文）", "## 5. Flag 收集",
                    "## 6. 总结与反思"]:
        assert section in md
    # 关键真实数据进入报告（新拓扑：入口机 192.168.100.2）
    assert "192.168.100.2" in md
    assert "flag{dmz_upload_pwn3d_7a91}" in md
    # 拓扑段已真实化：攻击端 IP 取自全局设置，不再写死「攻击端 127.0.0.1」桩
    assert "攻击端 127.0.0.1" not in md
    # 拓扑段应渲染出攻击机与主机树（攻击端标记为根）
    assert "攻击端" in md
    assert "✓已控" in md or "·未控" in md
    # 明文：凭据不再打码（用户指令，见 ASSUMPTIONS A-23）
    assert "root123" in md
    assert "***" not in md
    # 快照锚点：统计表包含行数
    assert "| 已控主机 |" in md


def test_export_json_snapshot(client, project_id):
    r = client.get("/api/export", params={"format": "json", "projectId": project_id})
    assert r.status_code == 200
    data = r.json()
    for key in ["project", "generatedAt", "stats", "segments", "hosts", "shells",
                "proxyLinks", "credentials", "flags", "timeline"]:
        assert key in data
    assert data["stats"]["aliveLinks"] >= 0
    # 明文：Shell 口令与凭据不再打码（用户指令，见 ASSUMPTIONS A-23）
    assert all(s["pass"] != "***" for s in data["shells"])
    assert any(s["pass"] for s in data["shells"])
    assert all(c["secret"] != "***" for c in data["credentials"])
    assert any(c["secret"] == "root123" for c in data["credentials"])


def test_export_html_snapshot(client, project_id):
    r = client.get("/api/export", params={"format": "html", "projectId": project_id})
    assert r.status_code == 200
    html = r.text
    assert html.startswith("<!DOCTYPE html>")
    assert "PivotHub 报告" in html
    assert "<pre>" in html and "</body></html>" in html


def test_export_rejects_bad_format(client):
    assert client.get("/api/export", params={"format": "pdf"}).status_code == 422
