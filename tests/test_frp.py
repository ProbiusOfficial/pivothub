"""frp 适配器测试：纯单元测试（离线）+ 真实本机回环 E2E（Socks5 反向隧道）。

约束：
- 仅新建本文件，不改动 pivothub/** / data/** / assets/** / index.html / tests/ 其它文件。
- 单测全部离线可跑；E2E 真实在本机 127.0.0.1 起 frps+frpc 并验证流量经隧道。
- 端口随机取空闲、带超时、确定性可重复；不依赖外网。
- 清理只杀本测试自己拉起的进程（按本次 auth token 精确定位），绝不无差别 taskkill。
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from pivothub.adapters.base import PidRecord
from pivothub.adapters.frp import (
    FrpAdapter,
    frpc_toml,
    frps_toml,
    proxy_socks5,
    proxy_tcp,
)
from pivothub.adapters.registry import get_adapter
from pivothub.config import TOOLS_DIR
from pivothub.session.base import ExecResult
from pivothub.session.local import LocalSession
from pivothub.util import proc_kill


class _DetachedLocalSession(LocalSession):
    """测试侧会话：继承 LocalSession，仅覆盖 exec 以避免 Windows PIPE 死锁。

    LocalSession.exec 用 capture_output=True（PIPE）拉起常驻 frpc.exe 时，frpc 会继承
    标准输出管道，导致 subprocess.run 的 communicate() 被永久阻塞（连 timeout 杀掉直接
    子进程后也无法解除，因为存活的 frpc 仍持有管道写端）——E2E 会假死。

    本覆盖把子进程 stdout/stderr 重定向到临时文件而非 PIPE：命令回显仍被捕获（供
    find_pids_cmd 精确定位 pid），但 frpc 不再继承会阻塞的管道，因而能真实在本地拉起
    frpc 并建链。仅测试侧使用，不改动 pivothub/** 任何代码。
    """

    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        start = time.perf_counter()
        out_f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".out", delete=False, encoding="utf-8", errors="replace")
        err_f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".err", delete=False, encoding="utf-8", errors="replace")
        out_path, err_path = out_f.name, err_f.name
        out_f.close()
        err_f.close()
        try:
            with open(out_path, "w", encoding="utf-8", errors="replace") as so, \
                 open(err_path, "w", encoding="utf-8", errors="replace") as se:
                proc = subprocess.run(
                    cmd, shell=True, stdout=so, stderr=se, timeout=timeout)
            ok = proc.returncode == 0
            err = ""
        except subprocess.TimeoutExpired:
            return ExecResult(ok=False, timed_out=True, error=f"命令超时（>{timeout}s）")
        except Exception as e:  # pragma: no cover
            return ExecResult(ok=False, error=str(e))
        finally:
            pass
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                out = f.read()
            with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                err = f.read()
        except OSError:
            out, err = "", ""
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
            try:
                os.unlink(err_path)
            except OSError:
                pass
        return ExecResult(ok=ok, output=(out + err).rstrip("\r\n"),
                          ms=int((time.perf_counter() - start) * 1000))


# --------------------------------------------------------------------------
# 工具：取空闲端口（用 bind(0) 让内核分配，TOCTOU 风险低，本地联调可接受）
# --------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _two_free_ports() -> tuple[int, int]:
    a = _free_port()
    while True:
        b = _free_port()
        if b != a:
            return a, b


# ==========================================================================
# A. 纯单元测试（不依赖二进制 / 网络，全部离线可跑）
# ==========================================================================

def test_frps_toml():
    """frps 配置：bindAddr / bindPort / auth.method=token / auth.token。"""
    txt = frps_toml("0.0.0.0", 7000, "tok123")
    assert 'bindAddr = "0.0.0.0"' in txt
    assert "bindPort = 7000" in txt
    assert 'auth.method = "token"' in txt
    assert 'auth.token = "tok123"' in txt


def test_frpc_toml():
    """frpc 配置：serverAddr / serverPort / loginFailExit=false，proxies 正确拼接。"""
    proxies = [proxy_socks5("socks5", 1080), proxy_tcp("pf", 9000, "10.0.0.5", 22)]
    txt = frpc_toml("127.0.0.1", 7000, "tok123", proxies)
    assert 'serverAddr = "127.0.0.1"' in txt
    assert "serverPort = 7000" in txt
    assert "loginFailExit = false" in txt
    # proxies 两段都被拼接进来
    assert 'name = "socks5"' in txt
    assert 'name = "pf"' in txt
    assert "remotePort = 1080" in txt
    assert "remotePort = 9000" in txt


def test_proxy_socks5():
    """socks5 代理声明：[[proxies]] + type=tcp + remotePort + [proxies.plugin] type=socks5。"""
    txt = proxy_socks5("s5", 1080)
    assert "[[proxies]]" in txt
    assert 'type = "tcp"' in txt
    assert "remotePort = 1080" in txt
    assert "[proxies.plugin]" in txt
    assert 'type = "socks5"' in txt


def test_proxy_tcp():
    """tcp 转发声明：localIP / localPort / remotePort。"""
    txt = proxy_tcp("pf", 9000, "10.0.0.5", 22)
    assert 'localIP = "10.0.0.5"' in txt
    assert "localPort = 22" in txt
    assert "remotePort = 9000" in txt


def test_generate_config_socks():
    """socks 链路：targetConf 含 socks5 plugin、remotePort==local_port；返回 dict 含全部键。"""
    a = FrpAdapter()
    out = a.generate_config(
        lhost="10.0.0.5", server_port=7000, local_port=1080,
        auth="pivothubabcd", link_type="socks",
    )
    for k in ("server", "target", "relay", "serverConf", "targetConf",
              "relayConf", "relayServerConf"):
        assert k in out, f"缺失键: {k}"
    assert '[proxies.plugin]' in out["targetConf"]
    assert 'type = "socks5"' in out["targetConf"]
    assert "remotePort = 1080" in out["targetConf"]
    # remotePort 应等于传入的 local_port
    assert "remotePort = 1080" in out["targetConf"]


def test_generate_config_portfwd():
    """portfwd 链路：targetConf 含 localIP=target_host / localPort=target_port / remotePort=local_port。"""
    a = FrpAdapter()
    out = a.generate_config(
        lhost="10.0.0.5", server_port=7000, local_port=9000,
        auth="pivothubabcd", link_type="portfwd",
        target_host="192.168.1.20", target_port=3389,
    )
    assert 'localIP = "192.168.1.20"' in out["targetConf"]
    assert "localPort = 3389" in out["targetConf"]
    assert "remotePort = 9000" in out["targetConf"]


def test_generate_config_relay():
    """relay 链路：targetConf 的 serverAddr==relay_addr、serverPort==relay_port；relayConf 含 localPort/remotePort==local_port。"""
    a = FrpAdapter()
    lport = 1080
    rp = 7001
    out = a.generate_config(
        lhost="10.0.0.5", server_port=7000, local_port=lport,
        auth="pivothubabcd", link_type="relay",
        relay_addr="10.9.9.9", relay_port=rp,
    )
    # 本层节点连上层跳板 frps#2
    assert f'serverAddr = "10.9.9.9"' in out["targetConf"]
    assert f"serverPort = {rp}" in out["targetConf"]
    # 跳板回连配置：把攻击机 <lport> 回映射到跳板自身
    assert f"localPort = {lport}" in out["relayConf"]
    assert f"remotePort = {lport}" in out["relayConf"]


def test_generate_config_respects_lhost():
    """generate_config 不写死 127.0.0.1 作为 lhost（显式传入非回环地址时应被原样使用）。"""
    a = FrpAdapter()
    lhost = "172.16.5.5"
    out = a.generate_config(
        lhost=lhost, server_port=7000, local_port=1080,
        auth="pivothubabcd", link_type="socks",
    )
    # targetConf 的 serverAddr 必须是显式传入的 lhost，而不是 127.0.0.1
    assert f'serverAddr = "{lhost}"' in out["targetConf"]
    assert 'serverAddr = "127.0.0.1"' not in out["targetConf"]


def test_bins_paths():
    """_bins：客户端二进制名正确，远端路径按平台拼接（linux 用 /，windows 用 \\）。"""
    a = FrpAdapter()
    # linux
    _s, cli_l, _d, rp_l = a._bins("linux")
    assert str(cli_l).endswith("frpc_linux")
    assert rp_l == "/tmp/.pivothub/frpc"
    # windows
    _s2, cli_w, _d2, rp_w = a._bins("windows")
    assert str(cli_w).endswith("frpc.exe")
    assert rp_w == r"%TEMP%\.pivothub\frpc.exe"
    # 显式 remote_dir 拼接
    _s3, _c3, _d3, rp3 = a._bins("linux", "/tmp/x")
    assert rp3 == "/tmp/x/frpc"
    _s4, _c4, _d4, rp4 = a._bins("windows", r"C:\t\x")
    assert rp4 == r"C:\t\x\frpc.exe"


def test_get_adapter_contract():
    """get_adapter('frp') 返回 FrpAdapter；link_types 含 socks/portfwd/relay。"""
    ad = get_adapter("frp")
    assert isinstance(ad, FrpAdapter)
    assert set(["socks", "portfwd", "relay"]).issubset(set(ad.link_types))


# ==========================================================================
# B. 真实本机回环 E2E（frp 反向 Socks5，验证流量真走隧道）
# ==========================================================================

BANNER = "PIVOTHUB-FRP-E2E"


class _EchoServer:
    """只回一行 banner 的 TCP echo server（连上即回 PIVOTHUB-FRP-E2E\\n）。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, banner: str = BANNER):
        self.host = host
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall((self.banner + "\n").encode("utf-8"))
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def start(self) -> "_EchoServer":
        self._t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._t.join(timeout=2)


def _frp_bins_present() -> bool:
    win = os.name == "nt"
    server = TOOLS_DIR / ("frps.exe" if win else "frps_linux")
    client = TOOLS_DIR / ("frpc.exe" if win else "frpc_linux")
    return server.exists() and client.exists()


@pytest.mark.skipif(not _frp_bins_present(),
                    reason="需要 frp 二进制（tools/frps*/frpc*）")
def test_frp_socks5_e2e_real_tunnel():
    """真实在本机建立 frp 反向 Socks5 隧道，并验证经隧道读到了目标 echo 回显。"""
    if os.name != "nt":
        pytest.skip("E2E 仅在 Windows 本机以 LocalSession(platform='windows') 回环验证")

    # 清除会触发 PowerShell Start-Process「哈希表键冲突」的大小写同名代理变量
    # （HTTPS_PROXY 与 https_proxy 等同名变量并存时，Start-Process 构造环境字典会抛异常，
    # 导致无法在目标侧拉起 frpc；仅清本测试进程环境，不影响系统/其它测试）。
    for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
               "ALL_PROXY", "all_proxy", "FTP_PROXY", "ftp_proxy"):
        os.environ.pop(_k, None)

    # 1) 起目标服务：本机 echo server（连上即回 banner）
    echo = _EchoServer(host="127.0.0.1", port=0, banner=BANNER).start()
    echo_port = echo.port
    time.sleep(0.3)  # 让监听就绪

    # 2) 取两个互相不冲突的空闲端口（frps bindPort / socks remotePort）
    server_port, local_port = _two_free_ports()

    # 3) 真实落地目录（绝对路径；LocalSession 的 upload_file 走 Python open，不可含 %TEMP%）
    remote_dir = tempfile.mkdtemp(prefix="pivothub_e2e_")

    session = _DetachedLocalSession(platform="windows")
    adapter = FrpAdapter()
    result = None
    used = {"server_port": server_port, "local_port": local_port, "echo_port": echo_port}

    try:
        result = adapter.deploy(
            session,
            target_ip="127.0.0.1",
            link_type="socks",
            lhost="127.0.0.1",
            server_port=server_port,
            local_port=local_port,
            bind_host="127.0.0.1",   # 只绑回环，避免 Windows 防火墙弹窗
            wait_s=25,
            verify=True,
            verify_target="127.0.0.1",
            verify_port=echo_port,
            remote_dir=remote_dir,
        )

        # 断言：部署成功 + 隧道验证成功 + banner 含目标回显
        assert result.ok is True, (
            f"部署失败: stage={result.stage} error={result.error} "
            f"log={result.log[-3:] if result.log else None}"
        )
        assert result.verify is not None, "缺少隧道验证结果"
        assert result.verify.ok is True, (
            f"隧道验证失败: {result.verify.error}"
        )
        assert BANNER in (result.verify.banner or ""), (
            f"隧道内未读到目标 banner，实际: {result.verify.banner!r}"
        )
        used["frps_pid"] = result.pid
        used["pids"] = [r.get("pid") if isinstance(r, dict) else getattr(r, "pid", None)
                        for r in result.pids]
        print(f"[E2E 证据] ports={used} banner={result.verify.banner!r}")
    finally:
        # 4) 无论如何都清理：只杀本测试拉起的 frp 进程 + 关 echo server + 删临时目录
        if result is not None:
            # 结束本机 frps
            if result.pid:
                proc_kill(result.pid)
            # 结束远端（本机）frpc 等
            for rec in result.pids:
                pid = rec.get("pid") if isinstance(rec, dict) else getattr(rec, "pid", None)
                role = rec.get("role") if isinstance(rec, dict) else getattr(rec, "role", "")
                if not pid or role == "server":
                    continue
                try:
                    session.kill_pid(int(pid))
                except Exception:
                    pass
            # 兜底：按本次 auth token 精确清理任何残留的 frps/frpc（不含他人进程）
            if result.auth:
                for img in ("frpc", "frps"):
                    for pid in session.find_pids_cmd(result.auth, image=img):
                        try:
                            session.kill_pid(pid)
                        except Exception:
                            pass
        echo.stop()
        shutil.rmtree(remote_dir, ignore_errors=True)

    # 5) 收尾校验：本测试相关进程应已全部退出（按 auth token 兜底复查）
    if result is not None and result.auth:
        leftover = []
        for img in ("frpc", "frps"):
            leftover += session.find_pids_cmd(result.auth, image=img)
        assert not leftover, f"存在残留 frp 进程未清理: {leftover}"
