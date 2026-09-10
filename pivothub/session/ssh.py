"""SSH 会话驱动（A7）：直接以 SSH 协议纳管一台主机（比 HTTP 一句话马更稳）。

认证：
- 优先私钥认证（key_path，可带 key_passphrase）；
- 否则密码认证（password）。
连接刻意不走本机 ssh-agent（look_for_keys=False, allow_agent=False），避免误用
操作者本机 agent 里的其它 key 去登录靶机。

平台识别：连接成功后跑 `uname -s` 探测，失败则按入参 / 主机 OS 推断。
文件操作优先走 SFTP（open_sftp）；若对端禁用了 SFTP 子系统，自动降级到
`ls -la` + base.parse_ls_output，与 HTTP 马 / 反弹通道保持同一份输出契约。

注意：本驱动经 paramiko 实现，全程无 subprocess（硬约束：命令执行只在会话层，
但 SSH 走的是网络协议而非本地进程）。
"""

from __future__ import annotations

import re
import stat
import time
from datetime import datetime
from typing import Optional

import paramiko

from .base import ExecResult, FileEntry, SessionBase, SessionError, b64d, \
    ls_error_text, parse_ls_output


#: 平台识别正则（与 reverse.py 的 detect_platform 保持一致口径）
_UNIX_RE = re.compile(r"\b(Linux|Darwin|FreeBSD|OpenBSD|NetBSD)\b", re.I)
_WIN_RE = re.compile(r"Windows|Microsoft", re.I)
_WIN_ERR_RE = re.compile(r"不是内部或外部命令|is not recognized|无法将|CommandNotFound", re.I)


def parse_ssh_url(url: str) -> tuple[str, str, int]:
    """解析 ssh://user@host:port → (user, host, port)；缺省端口 22。

    接受以下形态（均归一化）：
        ssh://root@10.0.0.5:2222
        root@10.0.0.5:2222
        ssh://10.0.0.5            （user 为空，端口 22）
    末尾若有空格或参数（数据库里偶发脏数据）一并裁掉。
    """
    s = (url or "").strip()
    if s.lower().startswith("ssh://"):
        s = s[len("ssh://"):]
    s = s.split(" ", 1)[0].split("#", 1)[0]  # 去尾随参数
    user = ""
    if "@" in s:
        user, s = s.split("@", 1)
    port = 22
    # 末个冒号后若是纯数字即端口（兼容 host:port 与 IPv4；IPv6 不在本期范围）
    if ":" in s:
        head, tail = s.rsplit(":", 1)
        if tail.isdigit():
            s = head
            port = int(tail)
    return user, s, port


class SshSession(SessionBase):
    kind = "ssh"

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        key_path: str = "",
        key_passphrase: str = "",
        platform: str = "",
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        self.platform = platform or "linux"
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._transport: Optional[paramiko.Transport] = None
        self._sftp = None
        self._connected = False
        self._hostname = ""

    # ---- 生命周期 ----

    def connect(self) -> None:
        """真实建立 SSH 连接（含认证）。失败抛带真实原因的 SessionError。"""
        if self._connected:
            return
        client = paramiko.SSHClient()
        # 靶场场景默认信任新主机密钥（避免首次连接卡在 missing host key）
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            kwargs: dict = dict(
                hostname=self.host, port=self.port, username=self.username,
                timeout=self.timeout, banner_timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            if self.key_path:
                kwargs["key_filename"] = self.key_path
                if self.key_passphrase:
                    kwargs["passphrase"] = self.key_passphrase
            else:
                kwargs["password"] = self.password
            client.connect(**kwargs)
        except paramiko.AuthenticationException as e:
            try:
                client.close()
            except Exception:
                pass
            raise SessionError(
                f"SSH 认证失败（用户名/密码/私钥不正确）：{e}"
            ) from e
        except paramiko.SSHException as e:
            try:
                client.close()
            except Exception:
                pass
            raise SessionError(f"SSH 协议错误：{e}") from e
        except OSError as e:
            try:
                client.close()
            except Exception:
                pass
            raise SessionError(f"SSH 连接失败 {self.host}:{self.port} - {e}") from e
        except Exception as e:  # 兜底：socket 超时等其它异常也要带真实原因
            try:
                client.close()
            except Exception:
                pass
            raise SessionError(f"SSH 连接失败 {self.host}:{self.port} - {e}") from e

        self._client = client
        self._transport = client.get_transport()
        self._connected = True
        # 连接后自动探测平台与主机名（失败保留入参/默认，不阻断纳管）
        self._post_connect_probe()

    def _post_connect_probe(self) -> None:
        """连接成功后探测平台与主机名（尽力而为，异常不阻断）。"""
        try:
            res = self.exec("uname -s 2>/dev/null; hostname 2>/dev/null", timeout=8)
            text = (res.output or "") + "\n" + (res.error or "")
        except Exception:
            return
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if _UNIX_RE.search(text):
            self.platform = "linux"
        elif _WIN_RE.search(text) or _WIN_ERR_RE.search(text):
            self.platform = "windows"
        # 主机名取最后一行非空（hostname 输出通常与 uname 分行）
        if lines:
            self._hostname = lines[-1]

    def _ensure_connected(self) -> None:
        if not self._connected:
            self.connect()

    def _sftp_open(self):
        if self._sftp is None:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self._transport = None
        self._connected = False

    # ---- SessionBase 抽象方法 ----

    def test(self) -> ExecResult:
        """连通性测试：真实跑一条命令，返回 ok 与耗时。"""
        return self.exec("echo __PIVOTHUB_ALIVE__")

    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        self._ensure_connected()
        start = time.perf_counter()
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            # 读取完整回显后取退出码（recv_exit_status 会等到对端关闭信道）
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
        except paramiko.SSHException as e:
            return ExecResult(ok=False, error=f"SSH 执行失败: {e}",
                              ms=int((time.perf_counter() - start) * 1000))
        except Exception as e:
            return ExecResult(ok=False, error=f"命令执行异常: {e}",
                              ms=int((time.perf_counter() - start) * 1000))
        return ExecResult(
            ok=rc == 0,
            output=(out or "").rstrip("\r\n"),
            error=(err or "").rstrip("\r\n"),
            ms=int((time.perf_counter() - start) * 1000),
        )

    def list_dir(self, path: str) -> list[FileEntry]:
        self._ensure_connected()
        try:
            sftp = self._sftp_open()
            attrs = sftp.listdir_attr(path)
        except (IOError, OSError, paramiko.SSHException):
            # SFTP 子系统被禁用：降级到 ls -la + 文本解析（与其它驱动契约一致）
            res = self.exec(f"ls -la --time-style=+%Y-%m-%d\\ %H:%M {path!r} 2>&1")
            if not res.ok:
                raise SessionError(res.error or "列目录失败")
            entries = [e for e in parse_ls_output(res.output) if e.name not in (".", "..")]
            if not entries:
                err = ls_error_text(res.output)
                if err:
                    raise SessionError(f"列目录失败: {err}")
            return entries
        entries: list[FileEntry] = []
        for a in attrs:
            name = a.filename
            if name in (".", ".."):
                continue
            is_dir = stat.S_ISDIR(a.st_mode)
            mtime = (datetime.fromtimestamp(a.st_mtime).strftime("%Y-%m-%d %H:%M")
                     if a.st_mtime else "")
            entries.append(FileEntry(name=name, is_dir=is_dir, size=a.st_size, mtime=mtime))
        return entries

    def read_file(self, path: str, max_bytes: int = 512 * 1024) -> str:
        self._ensure_connected()
        try:
            sftp = self._sftp_open()
            with sftp.open(path, "rb") as f:
                data = f.read(max_bytes)
        except (IOError, OSError, paramiko.SSHException) as e:
            raise SessionError(f"读取失败: {e}") from e
        return data.decode("utf-8", "replace")

    def write_file(self, path: str, content: str) -> None:
        self._ensure_connected()
        try:
            sftp = self._sftp_open()
            with sftp.open(path, "wb") as f:
                f.write(content.encode("utf-8"))
        except (IOError, OSError, paramiko.SSHException) as e:
            raise SessionError(f"写入失败: {e}") from e

    def write_file_b64(self, path: str, b64: str, append: bool = False) -> None:
        self._ensure_connected()
        try:
            sftp = self._sftp_open()
            with sftp.open(path, "ab" if append else "wb") as f:
                f.write(b64d(b64))
        except (IOError, OSError, paramiko.SSHException) as e:
            raise SessionError(f"二进制写入失败: {e}") from e

    def upload_file(self, path: str, data: bytes, chunk_size: int = 1_200_000) -> int:
        """SFTP 直传（比 base 分块 b64 高效）；返回写入字节数。"""
        self._ensure_connected()
        try:
            sftp = self._sftp_open()
            with sftp.open(path, "wb") as f:
                f.write(data)
        except (IOError, OSError, paramiko.SSHException) as e:
            raise SessionError(f"上传失败: {e}") from e
        return len(data)
