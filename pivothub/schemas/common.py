"""序列化工具：相对时间串 / HH:MM / 随机 ID。"""

from __future__ import annotations

import random
import string
from datetime import datetime


def rid(prefix: str) -> str:
    """与前端 rid() 同风格的新 ID：前缀-随机5位。"""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "-" + "".join(random.choices(alphabet, k=5))


def hhmm(dt: datetime | None) -> str:
    if not dt:
        return ""
    return f"{dt.hour:02d}:{dt.minute:02d}"


def beat_text(dt: datetime | None, alive: bool) -> str:
    """契约：'刚刚' / 'N 秒前' / 'N 分钟前'；断线加 '（断线）' 后缀。"""
    if dt is None:
        return "刚刚" if alive else "未知（断线）"
    delta = datetime.now() - dt
    sec = int(delta.total_seconds())
    if sec < 10:
        text = "刚刚"
    elif sec < 60:
        text = f"{sec} 秒前"
    elif sec < 3600:
        text = f"{sec // 60} 分钟前"
    else:
        text = f"{sec // 3600} 小时前"
    if not alive:
        text += "（断线）"
    return text
