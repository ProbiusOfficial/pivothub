"""内网应用指纹探测与目录/上下文发现。

设计要点（与 probe.py 一致）：
- 全部经 SessionBase.exec 在目标侧真实执行 HTTP 探测，解析真实回显（API 层零 subprocess）；
- 优先 curl，无 curl 时回退 python3（跨平台：Windows 直接走 python3）；
- dataclass + to_dict() 风格；结论不伪造——识别不出如实标 unknown，证据来自真实回显。

背景：靶场实测曾因只测了 Tomcat ROOT（404）就下「无应用」结论，漏掉部署在 /app 的
Shiro-550 应用。本模块专门补「应用级指纹」与「非 ROOT context 发现」两块能力。
"""

from __future__ import annotations

import base64
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from ..session.base import SessionBase


# ---------------------------------------------------------------------------
# 数据结构（dataclass + to_dict，对齐 probe.py 风格）
# ---------------------------------------------------------------------------

@dataclass
class FpProbe:
    """单个指纹检查的结果（ok=命中 / fail=已探测但非该应用 / unknown=无回显）。"""

    name: str
    state: str = "unknown"     # ok | fail | unknown
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "state": self.state, "evidence": self.evidence}


@dataclass
class AppItem:
    """单个目标（host:port）的应用指纹结论。"""

    target: str = ""
    status: int = 0            # HTTP 状态码，拿不到填 0
    app: str = ""              # 识别出的应用名；识别不出填 ""
    version: str = ""          # 版本；识别不出填 ""
    evidence: str = ""         # 关键证据片段（截断）
    probes: list[FpProbe] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target, "status": self.status, "app": self.app,
            "version": self.version, "evidence": self.evidence,
            "probes": [p.to_dict() for p in self.probes],
            "advice": list(self.advice),
        }


@dataclass
class ScanResult:
    items: list[AppItem] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "items": [i.to_dict() for i in self.items],
            "summary": dict(self.summary),
        }


@dataclass
class DirItem:
    """单个被探测路径的结果。"""

    url: str = ""
    status: int = 0
    length: int = 0
    title: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "status": self.status, "length": self.length,
                "title": self.title, "note": self.note}


@dataclass
class DirResult:
    items: list[DirItem] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "items": [i.to_dict() for i in self.items],
            "summary": dict(self.summary),
        }


# ---------------------------------------------------------------------------
# 探测清单与默认字典
# ---------------------------------------------------------------------------

#: 应用指纹探针： (标记, 相对根路径, 额外请求头)。顺序即优先级参考。
SCAN_PROBES = [
    ("BASE", "", ""),
    ("SHIRO", "", "Cookie: rememberMe=1"),
    ("JENKINS", "/api/json", ""),
    ("JENKINSCR", "/crumbIssuer/api/json", ""),
    ("NACOS", "/nacos/", ""),
    ("NACOSS", "/nacos/v1/console/server/state", ""),
    ("REG", "/v2/", ""),
    ("REGCAT", "/v2/_catalog", ""),
    ("ACT", "/actuator", ""),
    ("ACTENV", "/actuator/env", ""),
]

#: 精简但高价值的默认目录/上下文字典（必须覆盖的能力点）。
DEFAULT_DIRS = [
    # Tomcat 上下文
    "/app", "/manager/html", "/docs", "/examples", "/host-manager/html",
    # 通用
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/backup",
    "/admin", "/login", "/actuator", "/actuator/env",
    # 源码/配置备份
    "/static/app.py.bak", "/app.py.bak", "/www.zip", "/web.config.bak",
    "/index.php.bak", "/WEB-INF/web.xml",
]

_HTTP_RE = re.compile(r"^https?://[^\s'\"`]+$", re.I)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _deb64(s: str) -> str:
    """base64 解码（失败/空返回空串）。"""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def _snip(text: str, n: int = 200) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()[:n]


def _is_http_url(t: str) -> bool:
    return bool(_HTTP_RE.match((t or "").strip()))


def _norm_base(target: str) -> str:
    """去掉结尾多余斜杠，避免拼接出 //。"""
    t = (target or "").strip()
    if t.endswith("/") and not t.endswith("//"):
        t = t[:-1]
    return t


# ---------------------------------------------------------------------------
# 目标侧命令生成
# ---------------------------------------------------------------------------

def _py_scan_cmd(base: str) -> str:
    """python3 回退命令（跨平台）：base64 内嵌探针脚本，避免 shell 引号地狱。"""
    plines = ", ".join("(%r, %r, %r)" % (t, p, h) for t, p, h in SCAN_PROBES)
    src = (
        "import base64, ssl, sys, urllib.error, urllib.request\n"
        "try:\n  CTX = ssl._create_unverified_context()\n"
        "except Exception:\n  CTX = None\n"
        "BASE = '''__BASE__'''\n"
        + "PROBES = [%s]\n" % plines
        + PY_SCAN_BODY
    ).replace("__BASE__", base)
    b = base64.b64encode(src.encode("utf-8")).decode("ascii")
    return 'python3 -c "import base64,sys;exec(base64.b64decode(sys.argv[1]))" ' + b


def _py_dir_cmd(base: str, paths: list[str]) -> str:
    """python3 回退命令（目录发现）。"""
    plines = ",\n".join("  %r" % p for p in paths)
    src = (
        "import base64, re, ssl, sys, urllib.error, urllib.request\n"
        "try:\n  CTX = ssl._create_unverified_context()\n"
        "except Exception:\n  CTX = None\n"
        "BASE = '''__BASE__'''\n"
        + "PATHS = [\n%s\n]\n" % plines
        + PY_DIR_BODY
    ).replace("__BASE__", base)
    b = base64.b64encode(src.encode("utf-8")).decode("ascii")
    return 'python3 -c "import base64,sys;exec(base64.b64decode(sys.argv[1]))" ' + b


def _build_scan_cmd(base: str, platform: str) -> str:
    """对一个目标生成探测命令：Linux 优先 curl，无 curl 回退 python3；Windows 走 python3。"""
    base_q = shlex.quote(base)
    probe_fn = (
        "  _probe(){ u=\"$1\"; h=\"$2\"; tag=\"$3\"; bf=$(mktemp); hf=$(mktemp);\n"
        "    if [ -n \"$h\" ]; then ha=\"-H \\\"$h\\\"\"; else ha=\"\"; fi;\n"
        "    code=$(curl -s -m 6 -D \"$hf\" -o \"$bf\" -w '%{http_code}' $ha \"$u\" 2>/dev/null);\n"
        "    [ -z \"$code\" ] && code=0;\n"
        "    srv=$(grep -i '^Server:' \"$hf\" 2>/dev/null | head -1 | tr -d '\\r' | base64 | tr -d '\\n');\n"
        "    setc=$(grep -i '^Set-Cookie:' \"$hf\" 2>/dev/null | tr -d '\\r' | base64 | tr -d '\\n');\n"
        "    b=$(head -c 1500 \"$bf\" 2>/dev/null | base64 | tr -d '\\n');\n"
        "    rm -f \"$bf\" \"$hf\";\n"
        "    printf 'FP\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$tag\" \"$code\" \"$srv\" \"$setc\" \"$b\"; }\n"
    )
    calls = "\n".join(
        '  _probe %s %s "%s"' % (
            shlex.quote(base + path),
            ('"%s"' % hdr) if hdr else '""',
            tag,
        )
        for tag, path, hdr in SCAN_PROBES
    )
    py = _py_scan_cmd(base)
    if platform == "windows":
        return py
    return (
        "if command -v curl >/dev/null 2>&1; then\n"
        "  _base=%s\n" % base_q
        + probe_fn
        + calls + "\n"
        + "else\n  " + py.replace("\n", "\n  ") + "\nfi"
    )


def _build_dir_cmd(base: str, paths: list[str], platform: str) -> str:
    """对一个 base_url 生成目录/上下文探测命令（一次命令内循环，避免 N 次 exec）。"""
    base_q = shlex.quote(base)
    paths_str = " ".join(shlex.quote(p) for p in paths)
    if platform == "windows":
        return _py_dir_cmd(base, paths)
    py = _py_dir_cmd(base, paths)
    return (
        "if command -v curl >/dev/null 2>&1; then\n"
        "  _base=%s\n" % base_q
        + "  for p in " + paths_str + "; do\n"
        + '    u="$_base$p"; bf=$(mktemp);\n'
        + "    code=$(curl -s -m 6 -o \"$bf\" -w '%{http_code}' \"$u\" 2>/dev/null); [ -z \"$code\" ] && code=0;\n"
        + "    len=$(wc -c < \"$bf\" 2>/dev/null | tr -d ' '); [ -z \"$len\" ] && len=0;\n"
        + "    title=$(grep -ioE '<title>[^<]*</title>' \"$bf\" 2>/dev/null | head -1 | sed 's/<[^>]*>//g' | tr -d '\\r\\n' | base64 | tr -d '\\n');\n"
        + '    rm -f "$bf";\n'
        + "    printf 'DIR\\t%s\\t%s\\t%s\\t%s\\n' \"$code\" \"$len\" \"$title\" \"$p\";\n"
        + "  done\n"
        + "else\n  " + py.replace("\n", "\n  ") + "\nfi"
    )


# ---------------------------------------------------------------------------
# 回显解析
# ---------------------------------------------------------------------------

def _parse_scan_lines(out: str) -> dict[str, dict]:
    """FP 行 → {tag: {code, srv, setc, body}}。"""
    res: dict[str, dict] = {}
    for line in (out or "").splitlines():
        if not line.startswith("FP\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        tag = parts[1]
        try:
            code = int(parts[2])
        except ValueError:
            code = 0
        res[tag] = {
            "code": code,
            "srv": _deb64(parts[3]),
            "setc": _deb64(parts[4]),
            "body": _deb64(parts[5]),
        }
    return res


def _parse_dir_lines(out: str) -> list[tuple[int, int, str, str]]:
    """DIR 行 → [(code, length, title, path)]。"""
    items: list[tuple[int, int, str, str]] = []
    for line in (out or "").splitlines():
        if not line.startswith("DIR\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            code = int(parts[1])
        except ValueError:
            code = 0
        try:
            length = int(parts[2])
        except ValueError:
            length = 0
        items.append((code, length, _deb64(parts[3]), parts[4]))
    return items


def _tomcat_version(rec: dict) -> str | None:
    """从 Server 头/错误页识别 Tomcat；返回版本（可能为空串表示识别到但未知版本）。"""
    srv = rec.get("srv", "") or ""
    body = rec.get("body", "") or ""
    m = re.search(r"[Tt]omcat/?([0-9][0-9.]*[0-9])", srv + " " + body)
    if m:
        return m.group(1)
    if "coyote" in (srv + body).lower() or "apache tomcat" in body.lower():
        return ""   # 识别到 Tomcat，但拿不到版本
    return None


def _best_effort_app(rec: dict) -> dict | None:
    """Solr / Drupal / ThinkPHP / Flask 等尽力识别（仅在证据明确时判定，绝不硬猜）。"""
    body = rec.get("body", "") or ""
    low = body.lower()
    if "apache solr" in low or "solr admin" in low:
        return {"key": "solr", "app": "Solr", "evidence": "页面含 Apache Solr 标识",
                "advice": ["Solr 管理台暴露：核对版本对应 CVE（如 CVE-2019-17558 RCE）与未授权上传"]}
    if "content=\"drupal" in low or "<meta name=\"generator\" content=\"drupal" in low:
        return {"key": "drupal", "app": "Drupal", "evidence": "<meta generator=Drupal>",
                "advice": ["Drupal 站点：核对版本对应 CVE（如 CVE-2018-7600）与 /admin 暴露情况"]}
    if "thinkphp" in low or "页面错误！" in low:
        return {"key": "thinkphp", "app": "ThinkPHP", "evidence": "页面含 ThinkPHP 标识",
                "advice": ["ThinkPHP：按版本核对 RCE（如 5.x 远程代码执行），注意误开的 debug 模式"]}
    if "werkzeug debugger" in low or ("werkzeug" in low and "flask" in low):
        return {"key": "flask", "app": "Flask", "evidence": "Werkzeug/Flask 调试页",
                "advice": ["Flask 调试模式（Werkzeug）暴露：可直接执行代码，确认是否生产环境误开 debug"]}
    return None


def _dir_note(path: str) -> str:
    """路径 → 提示（源码备份 / 管理台 / 非 ROOT context 等）。"""
    low = (path or "").lower()
    # 源码 / 配置备份（优先级最高）
    if (re.search(r"\.(bak|zip|old|tar|gz|sql|tgz|config\.bak)$", low)
            or low.endswith("/.git/head")
            or low.endswith("/web-inf/web.xml")
            or low in ("/.env", "/web.config.bak", "/www.zip", "/index.php.bak",
                       "/app.py.bak", "/static/app.py.bak")):
        return "疑似源码/配置文件备份泄露（" + path + "）：可尝试下载还原，常含密钥与硬编码"
    if low in ("/actuator", "/actuator/env"):
        return "Spring Boot Actuator 端点暴露（可能泄露配置/堆转储，确认是否需鉴权）"
    if low in ("/manager/html", "/host-manager/html", "/docs", "/examples"):
        return "Tomcat 内置管理台/示例（" + path + "）：关注弱口令与 PUT 上传"
    seg = (path or "").strip("/")
    if seg and "/" not in seg and "." not in seg and path != "/":
        return ("疑似非 ROOT 的 Web 上下文（应用可能部署在 " + path
                + " 而非 ROOT）：务必枚举该 context 下的应用与接口")
    if low in ("/admin", "/login"):
        return "管理台/登录入口（" + path + "）"
    return ""


# ---------------------------------------------------------------------------
# 对外能力
# ---------------------------------------------------------------------------

def scan_apps(session: SessionBase, targets: list[str],
              timeout: float = 12.0) -> dict:
    """对每个目标在目标侧真实执行 HTTP 指纹探测，识别应用并给出建议。

    返回 {"items": [...], "summary": {...}}；识别不出如实标 app=""，严禁编造。
    """
    items: list[AppItem] = []
    for t in (targets or []):
        items.append(_scan_one(session, t, timeout))
    identified = [i for i in items if i.app]
    summary = {
        "total": len(items),
        "identified": len(identified),
        "unknown": sum(1 for i in items if not i.app),
        "apps": sorted({i.app for i in identified if i.app}),
    }
    return ScanResult(items=items, summary=summary).to_dict()


def _scan_one(session: SessionBase, target: str, timeout: float) -> AppItem:
    item = AppItem(target=target)
    base = _norm_base(target)
    if not _is_http_url(base):
        item.evidence = "目标格式非法（需以 http:// 或 https:// 开头）"
        item.probes = [FpProbe("format", "fail", item.evidence)]
        return item

    platform = getattr(session, "platform", "linux") or "linux"
    try:
        res = session.exec(_build_scan_cmd(base, platform), timeout=timeout)
    except Exception as e:  # 死靶/会话失败：如实记录，不假阳性
        item.evidence = f"探测执行失败：{e}"
        item.probes = [FpProbe("exec", "unknown", item.evidence)]
        return item

    parsed = _parse_scan_lines(res.output or "")
    app, version, evidence, matched_code, probes, advice = _detect_app(parsed)
    item.probes = probes
    item.advice = advice
    item.app = app
    item.version = version
    item.evidence = evidence
    base_rec = parsed.get("BASE")
    item.status = (base_rec["code"] if (base_rec and base_rec["code"]) else matched_code)
    if not app:
        if base_rec and base_rec["code"]:
            item.evidence = (f"根路径返回 {base_rec['code']}，"
                             "但未匹配 Shiro/Jenkins/Nacos/Registry/Actuator/Tomcat 等指纹"
                             + ("；已如实标注 unknown" if not base_rec["body"].strip() else ""))
        else:
            item.evidence = "目标无 HTTP 回显（超时/不可达），已如实标注 unknown"
    return item


def _detect_app(parsed: dict) -> tuple[str, str, str, int, list[FpProbe], list[str]]:
    """依据各探针真实回显判定应用（按优先级），返回 (app, version, evidence, matched_code, probes, advice)。"""
    probes: list[FpProbe] = []
    app = ""; version = ""; evidence = ""; matched_code = 0
    advice: list[str] = []

    # 1) Shiro：改包发 rememberMe=1，响应含 rememberMe=deleteMe → 判定
    shiro = parsed.get("SHIRO")
    if shiro:
        if "rememberme=deleteme" in (shiro["setc"] + shiro["body"]).lower():
            app = "Shiro"; matched_code = shiro["code"]
            evidence = "Set-Cookie: rememberMe=deleteMe（服务端用 Shiro 处理 rememberMe）"
            advice.append("疑似 Apache Shiro 且 Cookie 暴露 rememberMe=deleteMe：默认 Key "
                          "kPH+bIxk5D2deZiIxcaaaA== 可尝试 CVE-2016-4437 反序列化检测/利用")
            probes.append(FpProbe("shiro", "ok", evidence))
        else:
            probes.append(FpProbe("shiro", "fail", _snip(shiro["setc"] + shiro["body"])))
    else:
        probes.append(FpProbe("shiro", "unknown", ""))

    # 2) Jenkins：/api/json 匿名可读
    jen = parsed.get("JENKINS")
    if not app and jen and jen["code"] == 200 and '"nodeName"' in jen["body"]:
        app = "Jenkins"; matched_code = jen["code"]
        evidence = '匿名可读 /api/json（含 "nodeName"）'
        advice.append("Jenkins 匿名可读 /api/json → 检测匿名 Script Console（/script、/scriptText）"
                      "与凭据泄露；必要时按版本核对 CVE")
        probes.append(FpProbe("jenkins", "ok", evidence))
    elif jen:
        probes.append(FpProbe("jenkins", "fail" if jen["code"] else "unknown",
                               _snip(jen["body"]) if jen["code"] else "无回显/超时"))
    else:
        probes.append(FpProbe("jenkins", "unknown", ""))

    # 3) Nacos：首页与 /state
    nacos = parsed.get("NACOS"); nacos_s = parsed.get("NACOSS")
    nacos_hit = ((nacos and "nacos" in (nacos["body"] + nacos["srv"]).lower())
                 or (nacos_s and ("standalone" in nacos_s["body"].lower()
                                  or "nacos" in nacos_s["body"].lower())))
    if not app and nacos_hit:
        app = "Nacos"; matched_code = (nacos or nacos_s)["code"]
        evidence = "首页/state 暴露 Nacos 标识"
        advice.append("Nacos 控制台暴露：试 CVE-2021-29441（User-Agent: Nacos-Server 绕过鉴权）"
                      "探测 /nacos/v1/auth/users；默认口令 nacos/nacos")
        probes.append(FpProbe("nacos", "ok", evidence))
    elif nacos or nacos_s:
        rec = nacos or nacos_s
        probes.append(FpProbe("nacos", "fail" if rec["code"] else "unknown", _snip(rec["body"])))
    else:
        probes.append(FpProbe("nacos", "unknown", ""))

    # 4) Docker Registry：/v2/ 或 /v2/_catalog 未授权
    reg = parsed.get("REG"); regcat = parsed.get("REGCAT")
    reg_hit = ((reg and reg["code"] in (200, 401)
                and ("docker-distribution-api-version" in (reg["srv"] + reg["setc"]).lower()
                     or "repositories" in reg["body"].lower()))
               or (regcat and regcat["code"] in (200, 401)
                   and "repositories" in regcat["body"].lower()))
    if not app and reg_hit:
        app = "Docker Registry"; matched_code = (reg or regcat)["code"]
        evidence = "Docker Registry API v2 未授权可达（/v2/ 或 /v2/_catalog）"
        advice.append("Docker Registry 未授权：/v2/_catalog 可列镜像，拉取后解包可能含源码/密钥；"
                      "检查是否可 push")
        probes.append(FpProbe("docker-registry", "ok", evidence))
    elif reg or regcat:
        rec = reg or regcat
        probes.append(FpProbe("docker-registry", "fail" if rec["code"] else "unknown",
                               _snip(rec["body"])))
    else:
        probes.append(FpProbe("docker-registry", "unknown", ""))

    # 5) Spring Boot Actuator：/actuator 返回 JSON
    act = parsed.get("ACT"); actenv = parsed.get("ACTENV")
    act_hit = ((act and act["code"] == 200 and act["body"].lstrip().startswith("{"))
               or (actenv and actenv["code"] == 200 and actenv["body"].lstrip().startswith("{")))
    if not app and act_hit:
        app = "Spring Boot Actuator"; matched_code = (act or actenv)["code"]
        evidence = "/actuator 返回 JSON（疑似 Actuator 端点）"
        advice.append("Spring Boot Actuator 暴露：/actuator/env、/actuator/heapdump、"
                      "/actuator/configprops 等可能泄露配置与密钥；确认是否需鉴权")
        probes.append(FpProbe("spring-actuator", "ok", evidence))
    elif act or actenv:
        rec = act or actenv
        probes.append(FpProbe("spring-actuator", "fail" if rec["code"] else "unknown",
                               _snip(rec["body"])))
    else:
        probes.append(FpProbe("spring-actuator", "unknown", ""))

    # 6) Tomcat：Server 头/错误页识别版本（重点提示非 ROOT context）
    base = parsed.get("BASE")
    if not app and base:
        tv = _tomcat_version(base)
        if tv is not None:
            app = "Tomcat"; matched_code = base["code"]; version = tv
            evidence = "Server 头含 Tomcat" + (("/" + tv) if tv else "")
            advice.append("Tomcat 已识别（版本 " + (tv or "未知") + "）：应用可能部署在非 ROOT context"
                          "（如 /app）——务必用目录/上下文发现枚举；manager/html 弱口令与 PUT 上传、"
                          "CVE 按版本核对")
            probes.append(FpProbe("tomcat", "ok", evidence))
        else:
            probes.append(FpProbe("tomcat", "fail" if base["code"] else "unknown",
                                   _snip(base["body"])))
    elif not base:
        probes.append(FpProbe("tomcat", "unknown", ""))

    # 7) 其他（Solr / Drupal / ThinkPHP / Flask）：仅在证据明确时判定
    if not app and base:
        other = _best_effort_app(base)
        if other:
            app = other["app"]; evidence = other["evidence"]
            advice.extend(other["advice"])
            probes.append(FpProbe(other["key"], "ok", evidence))

    return app, version, evidence, matched_code, probes, advice


def discover_dirs(session: SessionBase, base_urls: list[str],
                  wordlist: list[str] | None = None, timeout: float = 12.0) -> dict:
    """对每个 base_url 在目标侧批量探测路径（一次命令内循环），发现应用上下文与备份。

    返回 {"items": [...], "summary": {"total", "hits"}}。
    """
    words = list(DEFAULT_DIRS)
    for w in (wordlist or []):          # 调用方覆盖/追加
        if w and w not in words:
            words.append(w)

    items: list[DirItem] = []
    for base in (base_urls or []):
        items.extend(_discover_one(session, base, words, timeout))

    hits = sum(1 for i in items if i.status and i.status != 404)
    summary = {"total": len(items), "hits": hits}
    return DirResult(items=items, summary=summary).to_dict()


def _discover_one(session: SessionBase, base_url: str, words: list[str], timeout: float
                  ) -> list[DirItem]:
    base = _norm_base(base_url)
    if not _is_http_url(base):
        return []
    platform = getattr(session, "platform", "linux") or "linux"
    try:
        res = session.exec(_build_dir_cmd(base, words, platform), timeout=timeout)
    except Exception:
        return []
    out = []
    for code, length, title, path in _parse_dir_lines(res.output or ""):
        out.append(DirItem(
            url=base + path, status=code, length=length, title=title,
            note=_dir_note(path),
        ))
    return out


# ---------------------------------------------------------------------------
# python3 回退脚本体内核（base64 内嵌，避免引号问题）
# ---------------------------------------------------------------------------

PY_SCAN_BODY = (
    "for tag, path, hdr in PROBES:\n"
    "    url = BASE + path\n"
    "    code = 0; srv = b''; setc = b''; body = b''\n"
    "    try:\n"
    "        req = urllib.request.Request(url)\n"
    "        if hdr:\n"
    "            for kv in hdr.split('\\r\\n'):\n"
    "                if ':' in kv:\n"
    "                    k, v = kv.split(':', 1)\n"
    "                    req.add_header(k.strip(), v.strip())\n"
    "        r = urllib.request.urlopen(req, timeout=6, context=CTX)\n"
    "        code = r.getcode(); body = r.read(1500)\n"
    "        srv = (r.headers.get('Server') or '').encode('utf-8', 'replace')\n"
    "        setc = (r.headers.get('Set-Cookie') or '').encode('utf-8', 'replace')\n"
    "    except urllib.error.HTTPError as e:\n"
    "        code = e.code\n"
    "        try: body = e.read(1500) or b''\n"
    "        except Exception: body = b''\n"
    "        if e.headers:\n"
    "            srv = (e.headers.get('Server') or '').encode('utf-8', 'replace')\n"
    "            setc = (e.headers.get('Set-Cookie') or '').encode('utf-8', 'replace')\n"
    "    except Exception:\n"
    "        code = 0\n"
    "    def b64(x):\n"
    "        return base64.b64encode(x).decode('ascii')\n"
    "    sys.stdout.write('FP\\t%s\\t%d\\t%s\\t%s\\t%s\\n' % (tag, code, b64(srv), b64(setc), b64(body)))\n"
)

PY_DIR_BODY = (
    "for p in PATHS:\n"
    "    url = BASE + p; code = 0; body = b''\n"
    "    try:\n"
    "        r = urllib.request.urlopen(urllib.request.Request(url), timeout=6, context=CTX)\n"
    "        code = r.getcode(); body = r.read(20000)\n"
    "    except urllib.error.HTTPError as e:\n"
    "        code = e.code\n"
    "        try: body = e.read(20000) or b''\n"
    "        except Exception: body = b''\n"
    "    except Exception:\n"
    "        code = 0\n"
    "    try:\n"
    "        t = re.search(rb'<title[^>]*>(.*?)</title>', body, re.I | re.S).group(1).decode('utf-8', 'replace')\n"
    "    except Exception:\n"
    "        t = ''\n"
    "    sys.stdout.write('DIR\\t%d\\t%d\\t%s\\t%s\\n' % (code, len(body), base64.b64encode(t.encode('utf-8')).decode(), p))\n"
)
