"""心跳/时间显示：库内 UTC naive 与展示层本地时钟的换算（UTC+8 下曾显示「8 小时前」）。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pivothub.schemas.common import beat_text, hhmm_utc


def _utc_now() -> datetime:
    """与 db.now() 同约定：UTC、naive。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def test_fresh_beat_is_just_now():
    """刚写的 last_beat_at（UTC）必须显示「刚刚」，而不是时差小时数。"""
    now = _utc_now()
    assert beat_text(now, True) == "刚刚"
    assert beat_text(now - timedelta(seconds=30), True) == "30 秒前"
    assert beat_text(now - timedelta(minutes=5), True) == "5 分钟前"
    assert beat_text(now - timedelta(hours=3), False) == "3 小时前（断线）"


def test_missing_beat_text():
    assert beat_text(None, True) == "刚刚"
    assert beat_text(None, False) == "未知（断线）"


def test_hhmm_utc_matches_local_clock():
    utc = _utc_now()
    assert hhmm_utc(utc) == datetime.now().strftime("%H:%M")
    assert hhmm_utc(None) == ""
