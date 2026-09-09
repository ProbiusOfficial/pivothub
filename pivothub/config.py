"""运行配置：路径、端口、数据库。全部可用环境变量覆盖。"""

from __future__ import annotations

import os
from pathlib import Path

# 项目根 = pivothub 包的上一级（原型 index.html 所在目录）
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PIVOTHUB_DATA_DIR", ROOT_DIR / "data"))
DB_PATH = Path(os.environ.get("PIVOTHUB_DB_PATH", ROOT_DIR / "pivothub.db"))

HOST = os.environ.get("PIVOTHUB_HOST", "127.0.0.1")
PORT = int(os.environ.get("PIVOTHUB_PORT", "8000"))

# 合规硬约束：面板只允许绑定回环地址
assert HOST in ("127.0.0.1", "localhost"), "PivotHub 仅允许监听 127.0.0.1（合规约束）"

DB_URL = os.environ.get("PIVOTHUB_DB_URL", f"sqlite:///{DB_PATH}")

DEFAULT_PROJECT_ID = os.environ.get("PIVOTHUB_PROJECT_ID", "proj-1")

BANNER = r"""
  ┌───────────────────────────────────────────────────────────┐
  │   PivotHub · 链透中枢 — 多层内网渗透辅助工具               │
  │                                                           │
  │   ⚠ 合规声明：本工具仅用于 CTF 竞赛 / 授权靶场 / 教学演示   │
  │     禁止对任何未授权的真实目标使用；面板仅监听 127.0.0.1，   │
  │     不对外暴露；不内置任何针对真实目标的 exploit。          │
  └───────────────────────────────────────────────────────────┘
"""


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def init_console() -> None:
    """让控制台能打印横幅（含 ⚠ / 中文）。

    Windows 默认 GBK 控制台无法编码 U+26A0 等字符，直接 `python -m pivothub`
    会抛 UnicodeEncodeError。这里把标准输出/错误切到 UTF-8 并开启替换，
    使用户无需设置 PYTHONIOENCODING 即可启动（完成标准第 1 条）。
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - 非 TTY / 旧解释器
            pass

# 本地工具二进制目录（chisel/frp 等），Adapter 部署时使用
TOOLS_DIR = Path(os.environ.get("PIVOTHUB_TOOLS_DIR", ROOT_DIR / "tools"))

# 文件暂存 HTTP 服务（上传「HTTP 拉取」通道）：目标机需回连本机，故默认监听 0.0.0.0，
# 端口 0 = 系统分配；只服务 /s/<随机 token>/<name> 路径，条目默认 15 分钟过期。
# 面板自身仍严格只监听 127.0.0.1（见上方 HOST 断言）。
STAGE_BIND = os.environ.get("PIVOTHUB_STAGE_BIND", "0.0.0.0")
STAGE_PORT = int(os.environ.get("PIVOTHUB_STAGE_PORT", "0"))
STAGE_TTL = int(os.environ.get("PIVOTHUB_STAGE_TTL", "900"))
STAGE_DIR = Path(os.environ.get("PIVOTHUB_STAGE_DIR", DATA_DIR / "stage"))
