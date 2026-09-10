"""提权智能匹配（PRD M5-2）：采集目标事实 → 命中规则库 → 给出可执行建议。

规则库是插件化数据（`data/privesc/*.json`），每条规则：

    {id, name, platform, risk, reliability, match, facts{kernel}, cmd, note}

- `match`：对「一次性采集命令的真实回显」做正则匹配（空串表示只看 facts）；
- `facts.kernel`：内核版本正则，不匹配则整条规则跳过；
- `excludeBasename`：basename 黑名单（如 SUID 的 `mount`/`umount`）。命中行
  若 basename 落在黑名单里，视为发行版默认状态而剔除；所有命中行都被剔除时规则整体不命中。
- 命中时返回证据行（回显里那一行），**只给建议与命令，不做任何自动利用**。
- `verify`/`expect`：可选的验证步骤。只有同时具备两者的规则才是 `verifiable`；
  匹配结果 `verified` 恒为 False（尚未在靶机实跑），无验证步骤的规则永远不得标记为「已执行」。
"""

from __future__ import annotations

import re
from typing import Any

from ..db import load_plugin_dir

#: 一次采集：尽量一条命令拿到判断提权所需的事实（经会话层真实执行）
LINUX_COLLECT = (
    "echo __PH_PRIVESC__; id; uname -a; (cat /etc/os-release 2>/dev/null | head -4); "
    "(sudo -n -l 2>&1 | head -20); (sudo --version 2>/dev/null | head -2); "
    "(find / -xdev -perm -4000 -type f 2>/dev/null | head -40); "
    "(getcap -r / 2>/dev/null | head -20); "
    "(find /etc/cron* /var/spool/cron -writable 2>/dev/null | head); "
    "(find /etc/passwd -writable 2>/dev/null)"
)

WINDOWS_COLLECT = (
    "whoami & hostname & whoami /priv & ver & "
    "(reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\" /v AlwaysInstallElevated 2>nul & "
    "reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\" /v AlwaysInstallElevated 2>nul) & "
    "(wmic service get name,pathname 2>nul | findstr /i \"Program Files\") & (cmdkey /list 2>nul)"
)


def collect_command(platform: str) -> str:
    return WINDOWS_COLLECT if platform == "windows" else LINUX_COLLECT


def load_rules(platform: str = "") -> list[dict]:
    """读规则库（data/privesc/*.json）；platform 过滤 linux / windows。"""
    rules = [r for r in load_plugin_dir("privesc") if isinstance(r, dict)]
    if platform:
        rules = [r for r in rules if (r.get("platform") or "linux") == platform]
    return rules


def parse_facts(output: str, platform: str) -> dict[str, Any]:
    """从采集回显提取事实：内核 / 发行版 / 权限 / 主机名。"""
    facts: dict[str, Any] = {"platform": platform, "kernel": "", "os": "",
                             "privilege": "", "hostname": ""}
    m = re.search(r"\bLinux \S+ ([\d][\w.\-]*)", output)
    if m:
        facts["kernel"] = m.group(1)
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', output)
    if m:
        facts["os"] = m.group(1).strip()
    if platform == "windows":
        m = re.search(r"Microsoft Windows[^\r\n]*", output)
        if m:
            facts["os"] = m.group(0).strip()[:120]
    m = re.search(r"uid=\d+\(([^)]+)\)", output)
    if m:
        facts["privilege"] = m.group(1)
    if not facts["privilege"]:
        m = re.search(r"^([A-Za-z0-9._-]+)\\([A-Za-z0-9._$-]+)\s*$", output, re.M)
        if m:
            facts["privilege"] = m.group(2)
    m = re.search(r"Linux \S+ \S+ .*? ([\w.-]+)\s*$", output, re.M)
    if m:
        facts["hostname"] = m.group(1)
    return facts


def _evidence(output: str, rx: re.Pattern, exclude_basenames: set[str] | None = None) -> str:
    """命中处的整行（截断 200 字符），作为「为什么命中」的证据。

    `exclude_basenames`：默认即带 SUID 的 basename 黑名单（如 mount/umount）。
    若提供，则跳过 basename 落在该名单里的命中行——这些只是发行版默认状态，
    并非真正的可利用线索，必须排除以免误报。返回第一条「非默认」的命中行；
    若所有命中行都被排除则返回空串（调用方据此判定规则整体未命中）。
    """
    for m in rx.finditer(output):
        start = output.rfind("\n", 0, m.start()) + 1
        end = output.find("\n", m.end())
        if end < 0:
            end = len(output)
        line = output[start:end].strip()
        if not line:
            continue
        if exclude_basenames:
            base = line.rsplit("/", 1)[-1].split()[0].lower()
            if base in exclude_basenames:
                continue
        return line[:200]
    return ""


def match_rules(platform: str, output: str, facts: dict | None = None) -> list[dict]:
    """按平台规则库匹配采集回显，返回命中项（可靠性降序）。

    回显先统一换行：反弹 PTY / Windows 目标常返回 CRLF，不归一化会让
    `(?m)^/etc/passwd$` 这类锚点规则漏报。
    """
    output = (output or "").replace("\r\n", "\n").replace("\r", "")
    facts = facts or parse_facts(output, platform)
    out: list[dict] = []
    for rule in load_rules(platform):
        f_rules = rule.get("facts") or {}
        kernel_rx = f_rules.get("kernel")
        if kernel_rx:
            try:
                if not re.search(kernel_rx, facts.get("kernel") or ""):
                    continue
            except re.error:
                continue
        pattern = rule.get("match") or ""
        #: 默认即带 SUID 的 basename 黑名单（Debian/Ubuntu 出厂状态），用于过滤误报。
        #: 仅对声明了该字段的规则生效（当前为 linux-suid）。
        exclude = {b.lower() for b in (rule.get("excludeBasename") or [])}
        evidence = ""
        if pattern:
            try:
                rx = re.compile(pattern, re.I | re.M)
            except re.error:
                continue
            if not rx.search(output):
                continue
            evidence = _evidence(output, rx, exclude or None)
            # 若规则声明了默认项黑名单，且所有命中行都是默认项 → 视为未命中（不误报）。
            if exclude and evidence == "":
                continue
        #: 规则是否自带「验证步骤」：只有 verify 与 expect 同时存在的规则才可被执行后验证。
        verifiable = bool(rule.get("verify") and rule.get("expect"))
        out.append({
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "platform": rule.get("platform", platform),
            "risk": rule.get("risk", "中"),
            "reliability": int(rule.get("reliability") or 0),
            "cmd": rule.get("cmd", ""),
            "note": rule.get("note", ""),
            #: 可选的验证步骤：执行 cmd 后再跑它，用 expect 正则判定是否真的拿到权限
            "verify": rule.get("verify", ""),
            "expect": rule.get("expect", ""),
            #: 可选：验证成功后可设置的提权上下文（后续命令以该用户执行）
            "escalate": rule.get("escalate") or {},
            "evidence": evidence,
            #: 是否已「执行并验证通过」。匹配阶段只是静态命中，尚未在靶机上跑过 verify，
            #: 因此一律为 False；且只有 verifiable 的规则才可能在后续被置 True——
            #: 没有验证步骤的规则永远无法被标记为「已执行/已验证」，前端据此避免误报。
            "verified": False,
            "verifiable": verifiable,
        })
    out.sort(key=lambda x: (-x["reliability"], x["name"]))
    return out
