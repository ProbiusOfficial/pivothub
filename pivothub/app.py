"""FastAPI 应用工厂：API 路由 + /ws + 原型静态托管。"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from . import config
from .api import api_router
from .db import get_session_factory, init_db
from .ws import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("pivothub.app")


async def _heartbeat_loop() -> None:
    """周期推送 shell.beat / link.state 快照（MS2 起接入真实探针）。"""
    from sqlalchemy import select

    from .models import ProxyLink, Shell
    from .schemas import ShellOut

    while True:
        try:
            await asyncio.sleep(10)
            if not manager.active:
                continue
            db = get_session_factory()()
            try:
                shells = db.query(Shell).filter(Shell.alive.is_(True)).all()
                for s in shells:
                    await manager.broadcast_raw(
                        {"type": "shell.beat", "shellId": s.id, "alive": True,
                         "latency": s.latency, "lastBeat": ShellOut.of(s).lastBeat}
                    )
                links = db.query(ProxyLink).filter(ProxyLink.status == "alive").all()
                for l in links:
                    await manager.broadcast_raw(
                        {"type": "link.state", "linkId": l.id, "status": l.status,
                         "latency": l.latency, "traffic": l.traffic}
                    )
            finally:
                db.close()
        except asyncio.CancelledError:
            return
        except Exception:  # pragma: no cover
            log.exception("心跳任务异常")


def _reset_reverse_shells() -> int:
    """启动时把历史「反弹 Shell」会话标记为断线。

    反连通道是进程内对象（socket），面板重启后必然失效；若不复位，列表里会残留
    「存活」绿点，用户点进去敲命令只会得到空回显 —— 状态必须与真实通道一致。
    """
    from .models import Shell

    db = get_session_factory()()
    try:
        rows = db.query(Shell).filter(Shell.kind == "reverse", Shell.alive.is_(True)).all()
        for s in rows:
            s.alive = False
            s.latency = 0
        if rows:
            db.commit()
        return len(rows)
    finally:
        db.close()


def _sync_local_machine() -> list[str]:
    """启动时把各项目的本机节点校正为当前真实机器（换机 / 换网后自动跟随）。"""
    from .localinfo import sync_local_machine

    db = get_session_factory()()
    try:
        changed = sync_local_machine(db)
        if changed:
            db.commit()
        return changed
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    reset = _reset_reverse_shells()
    if reset:
        log.info("已将 %d 个历史反弹 Shell 会话标记为断线（通道不跨进程存活）", reset)
    try:
        from .api.shells import restore_reverse_listeners

        rr = restore_reverse_listeners()
        if rr["restored"] or rr["failed"]:
            log.info("反弹监听恢复：%d 个已恢复，%d 个待重试", rr["restored"], len(rr["failed"]))
    except Exception:  # 恢复失败不阻塞面板启动
        log.exception("反弹监听恢复失败")
    synced = _sync_local_machine()
    if synced:
        log.info("已按本机真实信息更新本机节点 / 攻击机网卡：%s", ", ".join(sorted(set(synced))))
    manager.note_loop(asyncio.get_running_loop())
    task = asyncio.create_task(_heartbeat_loop())
    log.info("PivotHub 启动完成：http://%s:%s/", config.HOST, config.PORT)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # 文件暂存服务随面板退出关闭，并清掉未过期的暂存文件
    from .service import filestage

    filestage.STAGE.stop()


class NoCacheStaticFiles(StaticFiles):
    """本地面板静态资源：禁用浏览器缓存。

    面板是"改完代码立刻刷新看效果"的本地工具，JS/CSS 被缓存会导致「明明改了却还是旧行为」
    （第 5 轮就因此排查了一轮终端输入 bug）。这里统一返回 no-store，并关闭 304 协商。
    """

    def is_not_modified(self, response_headers, request_headers) -> bool:  # noqa: D102
        return False

    async def get_response(self, path, scope):  # noqa: D102
        resp = await super().get_response(path, scope)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp


def create_app() -> FastAPI:
    app = FastAPI(title="PivotHub · 链透中枢", version="0.1.0", lifespan=lifespan)

    @app.get("/api/health")
    async def health():
        return {"ok": True, "name": "PivotHub", "version": "0.1.0"}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await manager.connect(ws)
        try:
            while True:
                # 前端目前只收不发；保底读取以防缓冲堆积
                await ws.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(ws)
        except Exception:
            manager.disconnect(ws)

    app.include_router(api_router)

    # 原型静态托管（零构建）：index.html + assets 原样服务，路由级放在 API 之后
    app.mount("/", NoCacheStaticFiles(directory=str(config.ROOT_DIR), html=True), name="panel")
    return app


app = create_app()
