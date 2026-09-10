"""Neo-reGeorg 适配器单元测试（仅覆盖本适配器，不触碰他人并行改动）。"""

from __future__ import annotations

from pathlib import Path

from pivothub.adapters import NeoRegAdapter, get_adapter
from pivothub.adapters.base import DeployResult
from pivothub.session.base import SessionBase


class FakeSession(SessionBase):
    """最小假的会话：仅满足 deploy 调用契约（二进制缺失场景下不会用到写文件）。"""

    platform = "linux"

    def test(self):
        raise NotImplementedError

    def exec(self, cmd, timeout=15.0):
        raise NotImplementedError

    def list_dir(self, path):
        raise NotImplementedError

    def read_file(self, path, max_bytes=512 * 1024):
        raise NotImplementedError

    def write_file(self, path, content):
        raise NotImplementedError


def test_generate_config_keys_and_commands():
    """generate_config 应返回 key、tunnelUrl 拼接、generate/socks 命令形态。"""
    key = "a" * 32
    url = "http://10.0.0.5/upload/tunnel.php"
    cfg = NeoRegAdapter().generate_config(key=key, tunnel_url=url, local_port=1080)

    # key 长度（32 位十六进制）
    assert len(cfg["key"]) == 32

    # tunnelUrl 透传
    assert cfg["tunnelUrl"] == url

    # generate 命令形态
    assert "generate" in cfg["generate"]
    assert "-k " + key in cfg["generate"]
    assert "-o " in cfg["generate"]

    # socks 命令含 -k / -u / -p <port>，且端口正确
    socks = cfg["socks"]
    assert "-k " + key in socks
    assert "-u " + url in socks
    assert "-p 1080" in socks
    assert "-l 127.0.0.1" in socks

    # linkType 固定 socks
    assert cfg["linkType"] == "socks"


def test_generate_config_proxy_and_skip():
    """可选参数：skip_verify 加 -s，proxy 加 -x。"""
    cfg = NeoRegAdapter().generate_config(
        key="k", tunnel_url="http://x/t.php", local_port=9999,
        skip_verify=True, proxy="http://127.0.0.1:8080")
    assert "-s" in cfg["socks"]
    assert "-x http://127.0.0.1:8080" in cfg["socks"]


def test_link_types_contract():
    """Neo-reGeorg 仅声明 socks 链路类型。"""
    assert NeoRegAdapter().link_types == ("socks",)


def test_get_adapter_neoreg():
    """注册表能取到 Neo-reGeorg 实例。"""
    a = get_adapter("Neo-reGeorg")
    assert isinstance(a, NeoRegAdapter)
    assert a.tool == "Neo-reGeorg"


def test_lang_inference():
    """语言推断：Linux 默认 php，Windows 默认 aspx。"""
    a = NeoRegAdapter()
    assert a._lang_for("linux", "") == "php"
    assert a._lang_for("windows", "") == "aspx"
    assert a._lang_for("linux", "jsp") == "jsp"


def test_tunnel_url_join():
    """tunnel_url 拼接：web_root + 文件名。"""
    a = NeoRegAdapter()
    assert a._tunnel_url("10.0.0.5", "", "tunnel.php") == "http://10.0.0.5/tunnel.php"
    assert a._tunnel_url("10.0.0.5", "http://10.0.0.5/up", "tunnel.aspx") == \
        "http://10.0.0.5/up/tunnel.aspx"


def test_deploy_missing_binary():
    """未 vendor 成功（二进制缺失）时 deploy 返回 ok=False 且 stage=binary。"""
    # 指向不存在的 tools 目录，强制 _bins() 找不到 neoreg.py
    adapter = NeoRegAdapter(tools_dir=Path("/nonexistent_neoreg_tools_dir_xyz"))
    assert not adapter._bins().exists()

    sess = FakeSession()
    res = adapter.deploy(sess, target_ip="10.0.0.5", link_type="socks", local_port=1080,
                         verify=False)
    assert isinstance(res, DeployResult)
    assert res.ok is False
    assert res.stage == "binary"
    assert "neoreg.py" in res.error


def test_deploy_unsupported_link_type():
    """非 socks 链路类型应返回 stage=linkType。"""
    adapter = NeoRegAdapter(tools_dir=Path("/nonexistent_neoreg_tools_dir_xyz"))
    sess = FakeSession()
    res = adapter.deploy(sess, target_ip="10.0.0.5", link_type="portfwd")
    assert res.ok is False
    assert res.stage == "linkType"
