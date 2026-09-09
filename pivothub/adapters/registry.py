"""Adapter 注册表：工具名 → 适配器实例。"""

from __future__ import annotations

from .base import AdapterBase
from .chisel import ChiselAdapter

_REGISTRY: dict[str, type[AdapterBase]] = {
    "chisel": ChiselAdapter,
    # frp / Neo-reGeorg 随 MS3 补齐后在此注册
}


class AdapterError(Exception):
    pass


def get_adapter(tool: str) -> AdapterBase:
    cls = _REGISTRY.get(tool)
    if not cls:
        raise AdapterError(f"工具 {tool} 的 Adapter 尚未实现（已支持: {sorted(_REGISTRY)}）")
    return cls()
