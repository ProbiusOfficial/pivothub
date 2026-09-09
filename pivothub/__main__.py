"""python -m pivothub 入口：打印合规横幅与面板 URL，仅监听 127.0.0.1。"""

from __future__ import annotations

import webbrowser

from . import config


def main() -> None:
    config.init_console()
    print(config.BANNER)
    url = f"http://{config.HOST}:{config.PORT}/"
    print(f"  ✔ 面板地址：{url}")
    print(f"  ✔ 数据库　：{config.DB_PATH}")
    print("  按 Ctrl+C 停止服务\n")

    import uvicorn

    from .app import create_app

    if config.HOST == "127.0.0.1" and "--no-open" not in __import__("sys").argv:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    uvicorn.run(create_app(), host=config.HOST, port=config.PORT, log_level="warning")


if __name__ == "__main__":
    main()
