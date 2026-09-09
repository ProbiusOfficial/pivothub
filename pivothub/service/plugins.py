"""插件市场：清单（本地文件或远程 URL）→ 安装 / 启用 / 卸载。

插件是**数据插件**（命令库 / 马模板 / 固化技法 / 提权规则），安装后由
`db.load_plugin_dir` 自动并入对应视图；不在进程内执行任何第三方 Python 代码。

目录约定：

    data/plugins/registry.json          市场清单（可用 PIVOTHUB_PLUGIN_REGISTRY 指向远程 URL）
    data/plugins/<id>/plugin.json       已安装插件的元数据
    data/plugins/<id>/<sub>/<file>.json 插件贡献的数据（sub = commands/payloads/tty_fixes/privesc）
    data/plugins/<id>/.disabled         存在即视为停用
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .. import config

#: 允许插件贡献的数据子目录（与核心 data/<sub> 一致）
SUBS = ("commands", "payloads", "tty_fixes", "privesc")

PLUGIN_ROOT = config.DATA_DIR / "plugins"
REGISTRY_FILE = PLUGIN_ROOT / "registry.json"


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def registry_url() -> str:
    return os.environ.get("PIVOTHUB_PLUGIN_REGISTRY", "").strip()


def load_registry() -> dict:
    """市场清单：优先远程 URL，失败回落本地 registry.json（离线可用）。"""
    url = registry_url()
    if url:
        try:
            import httpx

            r = httpx.get(url, timeout=5.0)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("plugins"), list):
                data["source"] = url
                return data
        except Exception as e:  # 远程不可达不是错误：离线用本地清单
            local = _load_local_registry()
            local["remoteError"] = f"{url} 不可达：{e}"
            return local
    return _load_local_registry()


def _load_local_registry() -> dict:
    if REGISTRY_FILE.is_file():
        data = _read_json(REGISTRY_FILE)
        if isinstance(data, dict):
            data.setdefault("plugins", [])
            data["source"] = str(REGISTRY_FILE)
            return data
    return {"version": 1, "plugins": [], "source": ""}


def plugin_dir(pid: str) -> Path:
    return PLUGIN_ROOT / str(pid)


def is_installed(pid: str) -> bool:
    return (plugin_dir(pid) / "plugin.json").is_file()


def is_enabled(pid: str) -> bool:
    d = plugin_dir(pid)
    return (d / "plugin.json").is_file() and not (d / ".disabled").exists()


def installed() -> list[dict]:
    out: list[dict] = []
    if not PLUGIN_ROOT.is_dir():
        return out
    for d in sorted(PLUGIN_ROOT.iterdir()):
        meta_file = d / "plugin.json"
        if not d.is_dir() or not meta_file.is_file():
            continue
        try:
            meta = _read_json(meta_file)
        except Exception:
            continue
        meta = dict(meta or {})
        meta["id"] = meta.get("id") or d.name
        meta["enabled"] = not (d / ".disabled").exists()
        meta["path"] = str(d)
        out.append(meta)
    return out


def install(plugin: dict) -> dict:
    """把清单里的插件落到 data/plugins/<id>/（files 内联内容，覆盖安装）。"""
    pid = str(plugin.get("id") or "").strip()
    if not pid or "/" in pid or "\\" in pid or pid in (".", ".."):
        raise ValueError("插件 id 不合法")
    files = plugin.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("该插件没有可安装的内容（files 为空）")
    d = plugin_dir(pid)
    d.mkdir(parents=True, exist_ok=True)
    for item in files:
        rel = str((item or {}).get("path") or "").replace("\\", "/").strip("/")
        if not rel or ".." in rel.split("/"):
            raise ValueError(f"插件文件路径不合法: {rel}")
        if rel.split("/")[0] not in SUBS:
            raise ValueError(f"插件只能贡献 {SUBS} 下的数据文件，收到: {rel}")
        content = (item or {}).get("content")
        target = d / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, (dict, list)):
            _write_json(target, content)
        else:
            target.write_text(str(content or ""), encoding="utf-8")
    meta = {k: v for k, v in plugin.items() if k != "files"}
    meta["id"] = pid
    _write_json(d / "plugin.json", meta)
    (d / ".disabled").unlink(missing_ok=True)
    return {"id": pid, "installed": True, "files": len(files)}


def uninstall(pid: str) -> bool:
    d = plugin_dir(pid)
    if not d.is_dir():
        return False
    shutil.rmtree(d)
    return True


def set_enabled(pid: str, enabled: bool) -> bool:
    d = plugin_dir(pid)
    if not (d / "plugin.json").is_file():
        return False
    marker = d / ".disabled"
    if enabled:
        marker.unlink(missing_ok=True)
    else:
        marker.write_text("disabled\n", encoding="utf-8")
    return True


def contributions(sub: str) -> list[dict]:
    """已启用插件在某个数据子目录下的贡献（供 load_plugin_dir 合并）。"""
    items: list[dict] = []
    if sub not in SUBS or not PLUGIN_ROOT.is_dir():
        return items
    for d in sorted(PLUGIN_ROOT.iterdir()):
        if not d.is_dir() or (d / ".disabled").exists() or not (d / "plugin.json").is_file():
            continue
        sub_dir = d / sub
        if not sub_dir.is_dir():
            continue
        for p in sorted(sub_dir.glob("*.json")):
            try:
                data = _read_json(p)
            except Exception:
                continue
            if isinstance(data, list):
                items.extend(x for x in data if isinstance(x, dict))
            elif isinstance(data, dict):
                items.append(data)
    return items
