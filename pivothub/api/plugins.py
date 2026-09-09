"""插件市场 API：清单 / 安装 / 启停 / 卸载（数据插件，不执行第三方代码）。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..service import plugins as plugins_svc

router = APIRouter()


class ToggleIn(BaseModel):
    enabled: bool = True


@router.get("/plugins")
def plugins_list():
    """市场清单 + 已安装状态（远程清单不可达时回落本地并给出原因）。"""
    reg = plugins_svc.load_registry()
    installed = {p["id"]: p for p in plugins_svc.installed()}
    items = []
    for p in reg.get("plugins", []):
        pid = str(p.get("id") or "")
        if not pid:
            continue
        local = installed.get(pid)
        items.append({
            "id": pid,
            "name": p.get("name") or pid,
            "type": p.get("type") or (p.get("files") or [{}])[0].get("path", "").split("/")[0],
            "version": p.get("version", ""),
            "author": p.get("author", ""),
            "description": p.get("description", ""),
            "homepage": p.get("homepage", ""),
            "fileCount": len(p.get("files") or []),
            "installable": bool(p.get("files")),
            "installed": bool(local),
            "enabled": bool(local and local.get("enabled")),
        })
    # 本地已装但不在清单里的（手工放置 / 清单更新前安装的）也列出来
    known = {x["id"] for x in items}
    for pid, meta in installed.items():
        if pid in known:
            continue
        items.append({
            "id": pid, "name": meta.get("name") or pid, "type": meta.get("type", ""),
            "version": meta.get("version", ""), "author": meta.get("author", ""),
            "description": meta.get("description", ""), "homepage": "",
            "fileCount": 0, "installable": False, "installed": True,
            "enabled": bool(meta.get("enabled")),
        })
    return {
        "items": items,
        "registrySource": reg.get("source", ""),
        "registryUrl": plugins_svc.registry_url(),
        "remoteError": reg.get("remoteError", ""),
        "allowedDirs": list(plugins_svc.SUBS),
    }


@router.post("/plugins/{plugin_id}/install")
def plugins_install(plugin_id: str):
    reg = plugins_svc.load_registry()
    hit = next((p for p in reg.get("plugins", [])
                if str(p.get("id")) == plugin_id), None)
    if hit is None:
        raise HTTPException(404, f"清单中没有该插件: {plugin_id}")
    try:
        return {"ok": True, **plugins_svc.install(hit)}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.delete("/plugins/{plugin_id}")
def plugins_uninstall(plugin_id: str):
    if not plugins_svc.uninstall(plugin_id):
        raise HTTPException(404, f"插件未安装: {plugin_id}")
    return {"ok": True, "id": plugin_id}


@router.post("/plugins/{plugin_id}/toggle")
def plugins_toggle(plugin_id: str, form: ToggleIn):
    if not plugins_svc.set_enabled(plugin_id, form.enabled):
        raise HTTPException(404, f"插件未安装: {plugin_id}")
    return {"ok": True, "id": plugin_id, "enabled": form.enabled}
