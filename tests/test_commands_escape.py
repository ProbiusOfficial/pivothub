"""容器逃逸 / 容器内提权命令包校验。

复用 pivothub.db.load_plugin_dir（与前端 init() 同一条加载链路）来解析
data/commands/*.json，避免自造 JSON 解析器。仅断言我们新增的
container-escape.json 的字段完整性、id 唯一性与 cmd 非空。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pivothub.db import load_plugin_dir

COMMANDS_DIR = Path(__file__).resolve().parents[1] / "data" / "commands"
ESCAPE_FILE = COMMANDS_DIR / "container-escape.json"

# 命令库约定字段（与现有 lateral.json / linux-privesc.json 一致）
REQUIRED_FIELDS = ("id", "category", "os", "title", "cmd", "note")


def _load_escape_file() -> list[dict]:
    """直接读取新文件，作为单一来源断言（绕过插件合并噪音）。"""
    with open(ESCAPE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list), "顶层必须是数组"
    return data


def test_escape_file_is_valid_json_array():
    """container-escape.json 可被标准 json 解析且为数组。"""
    data = _load_escape_file()
    assert len(data) >= 1, "命令包不应为空"


def test_escape_entries_have_required_fields():
    """每条命令字段齐全（与现有命令库 schema 完全一致）。"""
    for entry in _load_escape_file():
        for field in REQUIRED_FIELDS:
            assert field in entry, f"缺少字段 {field}: {entry!r}"
        assert isinstance(entry["id"], str) and entry["id"], f"id 非法: {entry!r}"
        assert isinstance(entry["cmd"], str) and entry["cmd"].strip(), \
            f"cmd 必须非空字符串: {entry!r}"
        # note 允许为空字符串（与现有文件一致），但必须是字符串
        assert isinstance(entry["note"], str), f"note 必须为字符串: {entry!r}"


def test_escape_ids_unique_within_file():
    """文件内 id 唯一。"""
    ids = [e["id"] for e in _load_escape_file()]
    assert len(ids) == len(set(ids)), f"文件内 id 重复: {ids}"


def test_escape_ids_do_not_collide_with_repo_commands():
    """通过 load_plugin_dir 合并全部命令库，跨文件 id 仍唯一。"""
    all_cmds = load_plugin_dir("commands")
    ids = [c.get("id") for c in all_cmds]
    assert len(ids) == len(set(ids)), f"跨命令库 id 冲突: {ids}"


def test_escape_loaded_via_plugin_dir():
    """新文件确实被 load_plugin_dir 加载（接线后即可被前端读取）。"""
    all_cmds = load_plugin_dir("commands")
    escape_ids = {e["id"] for e in _load_escape_file()}
    loaded_ids = {c["id"] for c in all_cmds}
    assert escape_ids <= loaded_ids, "新命令包未被 load_plugin_dir 加载"


def test_escape_covers_required_scenarios():
    """覆盖任务要求的全部场景（按 ce 编号区间大致校验）。"""
    ids = {e["id"] for e in _load_escape_file()}
    # docker.sock / 特权 / PwnKit / cron / capabilities / 可写凭据 / k8s 各至少命中
    assert "ce-1" in ids and "ce-5" in ids   # docker.sock 检测与逃逸
    assert "ce-6" in ids and "ce-9" in ids   # dind / 特权容器
    assert "ce-10" in ids and "ce-11" in ids # PwnKit
    assert "ce-12" in ids and "ce-14" in ids # cron 劫持
    assert "ce-15" in ids and "ce-16" in ids # capabilities 提权
    assert "ce-17" in ids and "ce-19" in ids # 可写文件与凭据泄露
    assert "ce-20" in ids                    # Kubernetes 侧（可选）
