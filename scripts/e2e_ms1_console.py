"""MS1 端到端验收（Playwright）：11 个视图在真实接口驱动下的控制台检查。

前置：python -m pivothub 已启动（127.0.0.1:8000）。
运行：python scripts/e2e_ms1_console.py
通过标准：
  1. 数据来自后端 API（apiMode=true，WS 在线，实体计数 > 0）；
  2. 逐个切换 11 个视图 + Shell 终端交互，浏览器控制台 0 错误 0 警告。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from playwright.sync_api import sync_playwright  # noqa: E402

BASE = "http://127.0.0.1:8000/"
VIEWS = [
    "dashboard", "topology", "shell", "generator", "proxy",
    "asset", "cred", "flag", "timeline", "cheat", "export",
]


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1680, "height": 1050})
        page.on("console", lambda m: (errors if m.type == "error" else warnings).append(f"[console.{m.type}] {m.text}")
                if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))

        page.goto(BASE)
        page.wait_for_selector(".main", timeout=15000)
        # 关闭合规声明
        page.evaluate("PivotStore.state.ui.disclaimerOpen = false")
        page.wait_for_timeout(1500)  # 等 API 状态 + WS

        report = page.evaluate(
            """(() => {
              const S = PivotStore;
              return {
                apiMode: S.isApiMode ? S.isApiMode() : false,
                wsOnline: S.state.ws.online,
                hosts: S.state.hosts.length,
                shells: S.state.shells.length,
                links: S.state.links.length,
                creds: S.state.creds.length,
                flags: S.state.flags.length,
                timeline: S.state.timeline.length,
                commands: S.state.commands.length,
                ttyFixes: S.state.ttyFixes.length,
                injectTips: S.state.injectTips.length,
                shellBeat: S.state.shells[0] ? S.state.shells[0].lastBeat : null,
              };
            })()"""
        )
        print("数据源检查:", report)

        for v in VIEWS:
            page.evaluate(f"PivotStore.state.ui.view = '{v}'")
            page.wait_for_timeout(1200 if v == "shell" else 700)
            if v == "shell":
                page.evaluate(
                    "PivotStore.openTerminalById(PivotStore.state.shells.find(s=>s.alive).id)"
                )
                page.wait_for_timeout(900)
                page.evaluate("PivotStore.execCommand('id')")
                page.wait_for_timeout(800)
            if v == "topology":
                page.evaluate("PivotStore.selectHost(PivotStore.state.hosts[1].id)")
                page.wait_for_timeout(400)

        browser.close()

    print(f"控制台错误 {len(errors)} 个 / 警告 {len(warnings)} 个")
    for e in errors[:20]:
        print("  E>", e)
    for w in warnings[:20]:
        print("  W>", w)

    ok = (
        not errors
        and not warnings
        and report["apiMode"]
        and report["wsOnline"]
        and report["hosts"] > 0
        and report["commands"] >= 16
        and report["ttyFixes"] == 13
    )
    print("E2E-MS1-CONSOLE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
