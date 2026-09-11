"""序列化工具：相对时间串 / HH:MM / 随机 ID。"""

from __future__ import annotations

import random
import string
from datetime import datetime, timezone


def rid(prefix: str) -> str:
    """与前端 rid() 同风格的新 ID：前缀-随机5位。"""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "-" + "".join(random.choices(alphabet, k=5))


def hhmm(dt: datetime | None) -> str:
    """按库里的原值格式化为 HH:MM（**调用方须确认该字段存的是本地时间**）。

    ⚠ 本项目两种时间约定并存：db.now() 写 **UTC naive**（Shell/Credential/Flag），
    而 Timeline.ts 用 datetime.now 默认值写 **本地 naive**。UTC 来源必须走
    hhmm_utc()，否则 UTC+8 环境下显示的时间会比实际早 8 小时。
    """
    if not dt:
        return ""
    return f"{dt.hour:02d}:{dt.minute:02d}"


def hhmm_utc(dt: datetime | None) -> str:
    """UTC naive（db.now() 写入）→ 本地 HH:MM。"""
    if not dt:
        return ""
    return hhmm(dt.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None))


def beat_text(dt: datetime | None, alive: bool) -> str:
    """契约：'刚刚' / 'N 秒前' / 'N 分钟前'；断线加 '（断线）' 后缀。

    ⚠ 时间基准：库里存的是 **UTC naive**（db.now() = datetime.now(timezone.utc)），
    这里必须用 UTC 相减——此前用本地 now() 比，UTC+8 环境下刚心跳的会话也会显示
    「8 小时前」，刚回连登记的反弹会话看起来像旧的。
    """
    if dt is None:
        return "刚刚" if alive else "未知（断线）"
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
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
