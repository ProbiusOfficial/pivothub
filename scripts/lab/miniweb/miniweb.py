"""miniweb — 本地联调靶（stdlib 实现，零依赖）。

提供一个「真实执行」的 WebShell 目标：与真实 PHP 一句话马使用完全相同的
POST 协议（字段=连接密码，值为 PHP 代码载荷）。服务器端解释 PivotHub 驱动
生成的规范载荷模式（exec/scandir/读文件/写文件），以真实子进程 + 真实文件系统
执行 —— 用于本机（无 Docker/PHP 环境）验证会话协议栈与终端固化全流程。

⚠ 合规：仅用于 CTF / 授权靶场 / 教学。仅监听 127.0.0.1。

用法：
    python scripts/lab/miniweb/miniweb.py --port 8787 --pwd cmd --dir ./wwwroot
然后面板登记 Shell：
    URL: http://127.0.0.1:8787/shell.php   密码: cmd   类型: PHP 一句话马
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

EOF_MARK = "[[PIVOTHUB_EOF]]"
B64_ARG_RE = re.compile(r'base64_decode\("([A-Za-z0-9+/=]+)"\)')


def php_exec(cmd: str) -> str:
    """真实子进程执行（Windows 走 cmd / POSIX 走 sh）。"""
    try:
        proc = subprocess.run(
            cmd + " 2>&1", shell=True, capture_output=True, timeout=25,
            text=True, errors="replace",
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "[miniweb] 命令超时"


def php_scandir(d: str) -> str:
    lines = []
    try:
        names = sorted(os.listdir(d))
    except OSError as e:
        return f"[miniweb] scandir 失败: {e}"
    for name in names:
        if name == ".":
            continue
        full = os.path.join(d, name)
        try:
            st = os.stat(full)
            is_dir = os.path.isdir(full)
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            size = 0 if is_dir else st.st_size
        except OSError:
            is_dir, size, mtime = False, 0, ""
        lines.append("%s\t%d\t%s\t%s" % (
            "d" if is_dir else "-", size, mtime,
            base64.b64encode(name.encode("utf-8", "replace")).decode("ascii"),
        ))
    return "\n".join(lines)


def php_read(f: str, max_bytes: int = 512 * 1024) -> str:
    try:
        with open(f, "rb") as fh:
            return base64.b64encode(fh.read(max_bytes)).decode("ascii")
    except OSError as e:
        return "PIVOTHUB_READ_FAIL:" + str(e)


def php_write(f: str, content_b64: str, append: bool = False) -> str:
    try:
        data = base64.b64decode(content_b64)
        os.makedirs(os.path.dirname(os.path.abspath(f)), exist_ok=True)
        with open(f, "ab" if append else "wb") as fh:
            fh.write(data)
        return "PIVOTHUB_WRITE_OK"
    except OSError as e:
        return "PIVOTHUB_WRITE_FAIL:" + str(e)


def interpret_php(payload: str) -> str:
    """按 PivotHub 驱动的规范载荷模式解释执行（模式外的 PHP 代码不识别）。"""
    out: list[str] = []
    if payload.startswith('$c=base64_decode("'):
        args = B64_ARG_RE.findall(payload)
        if args:
            import html as _html

            cmd = base64.b64decode(args[0]).decode("utf-8", "replace")
            out.append(php_exec(cmd))
    elif payload.startswith("$d=base64_decode(\"") and "scandir" in payload:
        args = B64_ARG_RE.findall(payload)
        if args:
            d = base64.b64decode(args[0]).decode("utf-8", "replace")
            out.append(php_scandir(d))
    elif payload.startswith("$f=base64_decode(\"") and "fread" in payload:
        args = B64_ARG_RE.findall(payload)
        if args:
            out.append(php_read(base64.b64decode(args[0]).decode("utf-8", "replace")))
    elif payload.startswith("$r=@file_put_contents("):
        args = B64_ARG_RE.findall(payload)
        if len(args) >= 2:
            # 第三个实参是 PHP 的 FILE_APPEND 常量（1）或 0 —— 与真实马一致的分块追加语义
            append = ",FILE_APPEND" in payload.replace(" ", "")
            out.append(php_write(
                base64.b64decode(args[0]).decode("utf-8", "replace"), args[1], append))
    elif payload.startswith('echo "'):
        pass  # 连通性探针
    return "\n".join(out)


class Handler(BaseHTTPRequestHandler):
    server_version = "miniweb/1.0"
    pwd = "cmd"
    docroot = "."

    def log_message(self, fmt, *args):  # 安静模式
        sys.stderr.write("[miniweb] %s %s\n" % (self.address_string(), fmt % args))

    def _respond(self, text: str, status: int = 200) -> None:
        body = text.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        self._respond(f"<!-- miniweb target · {path} -->")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        fields = parse_qs(raw, keep_blank_values=True)
        payload = fields.get(Handler.pwd, [""])[0] or fields.get("cmd", [""])[0] \
            or fields.get("pass", [""])[0]
        if not payload:
            self._respond("[miniweb] 缺少载荷字段", 400)
            return
        try:
            result = interpret_php(payload)
        except Exception as e:  # 靶机异常也要回显，便于驱动诊断
            result = f"[miniweb] 解释异常: {e}"
        self._respond(result + "\n" + EOF_MARK)


def main() -> None:
    ap = argparse.ArgumentParser(description="miniweb 本地联调靶（仅 127.0.0.1）")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--pwd", default="cmd", help="一句话马连接密码（POST 字段名）")
    ap.add_argument("--dir", default=".", help="文档根目录")
    args = ap.parse_args()

    Handler.pwd = args.pwd
    Handler.docroot = os.path.abspath(args.dir)
    os.chdir(Handler.docroot)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[miniweb] 目标已就绪: http://127.0.0.1:{args.port}/shell.php  "
          f"(密码/字段: {args.pwd} · 根目录: {Handler.docroot})")
    print("[miniweb] 仅用于 CTF / 授权靶场 / 教学")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
