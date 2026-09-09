"""代理工具适配器：统一生命周期（generate_config → deploy → wait_callback →
register_link → health_check → destroy）。

硬约束：subprocess 只出现在本层（adapters）与 session 层，绝不进入 api/ 路由。
一期真实实现：chisel（frp / Neo-reGeorg 随 MS3 后续补齐，接口一致）。
"""

from .base import LINK_TYPES, AdapterBase, DeployResult, PidRecord, TunnelCheck
from .chisel import ChiselAdapter, pick_lhost, port_open, read_banner, socks5_read_banner
from .registry import AdapterError, get_adapter

__all__ = [
    "AdapterBase", "DeployResult", "PidRecord", "TunnelCheck", "LINK_TYPES",
    "ChiselAdapter", "pick_lhost", "port_open", "read_banner", "socks5_read_banner",
    "AdapterError", "get_adapter",
]
