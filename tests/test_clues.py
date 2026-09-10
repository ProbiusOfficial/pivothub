"""配置文件线索检索：解析单测（fake session）+ 一条 TestClient 冒烟。

fake session 实现 exec(cmd, timeout) 返回可控 ExecResult，覆盖：
- Linux grep -n 伪造回显 → 解析出正确 file/line/text/keyword；
- 无命中 → ok:true 且 items==[]；
- 命令执行失败 → ok:false + 非空 error。
"""

from __future__ import annotations

from pivothub.session.base import ExecResult
from pivothub.service import clues as C


class FakeSession:
    """可控假会话：按命令关键字返回预设回显，模拟目标侧真实执行。"""

    def __init__(self, platform: str = "linux", *, grep: str = "",
                 enum: str = "", fail: bool = False, fail_msg: str = "boom"):
        self.platform = platform
        self._grep = grep
        self._enum = enum
        self._fail = fail
        self._fail_msg = fail_msg
        self.last_cmd: str = ""

    def exec(self, cmd: str, timeout: float = 30.0) -> ExecResult:
        self.last_cmd = cmd
        if self._fail:
            return ExecResult(ok=False, error=self._fail_msg)
        if "grep" in cmd or "findstr" in cmd:  # Linux grep / Windows findstr 通道
            return ExecResult(ok=True, output=self._grep)
        if "stat -c" in cmd:                   # Linux 候选文件枚举（size+path）
            return ExecResult(ok=True, output=self._enum)
        if "Get-ChildItem" in cmd:             # Windows 取 size
            return ExecResult(ok=True, output="")
        return ExecResult(ok=True, output="")


LINUX_GREP = (
    "/var/www/html/application/extra/ops.php:11:'pass'    => 'REDACTED',\n"
    "/var/www/html/application/extra/ops.php:9:'admin'   => 'admin',\n"
    "/var/www/html/application/extra/ops.php:12:'user'    => 'admin',\n"
)
LINUX_ENUM = "412 /var/www/html/application/extra/ops.php\n"


def test_linux_parse_real_line_numbers():
    sess = FakeSession("linux", grep=LINUX_GREP, enum=LINUX_ENUM)
    out = C.search_clues(sess, timeout=10.0)
    assert out["ok"] is True, out
    assert out["error"] == ""
    items = out["items"]
    assert len(items) == 1
    it = items[0]
    assert it["file"] == "/var/www/html/application/extra/ops.php"
    assert it["size"] == 412
    # 命中按真实行号升序：9, 11, 12
    lines = [(h["line"], h["text"], h["keyword"]) for h in it["hits"]]
    assert lines == [
        (9, "'admin'   => 'admin',", "admin"),
        (11, "'pass'    => 'REDACTED',", "pass"),
        (12, "'user'    => 'admin',", "user"),
    ]
    # 默认字典规模：17 关键词 + 10 个 Linux 根
    assert out["summary"]["keywords"] == C.DEFAULT_KEYWORDS
    assert len(out["summary"]["keywords"]) == 17
    assert out["summary"]["roots"] == C.DEFAULT_ROOTS_LINUX
    assert out["summary"]["filesHit"] == 1
    assert out["summary"]["hitCount"] == 3


def test_no_hit_returns_ok_with_empty_items():
    sess = FakeSession("linux", grep="", enum="100 /etc/some.conf\n")
    out = C.search_clues(sess, timeout=10.0)
    assert out["ok"] is True
    assert out["items"] == []
    assert out["summary"]["filesHit"] == 0
    assert out["summary"]["hitCount"] == 0


def test_exec_failure_returns_ok_false_with_error():
    sess = FakeSession("linux", grep=LINUX_GREP, enum=LINUX_ENUM, fail=True,
                       fail_msg="目标侧命令执行失败（无回显 / 被拦截）")
    out = C.search_clues(sess, timeout=10.0)
    assert out["ok"] is False
    assert out["error"] == "目标侧命令执行失败（无回显 / 被拦截）"
    assert out["items"] == []


def test_windows_parse_path_with_drive_colon():
    # Windows findstr 回显含盘符冒号：C:\x\file.php:11:text
    win_grep = r"C:\inetpub\www\conf.php:3:$pass = 'REDACTED';\n"
    sess = FakeSession("windows", grep=win_grep)
    out = C.search_clues(sess, timeout=10.0)
    assert out["ok"] is True
    it = out["items"][0]
    assert it["file"] == r"C:\inetpub\www\conf.php"
    assert it["hits"][0]["line"] == 3
    assert it["hits"][0]["keyword"] == "pass"


# ---------------------------------------------------------------------------
# TestClient 冒烟：在进程内重新装载（含 clues 路由，位于静态挂载之前）→ 验证
# 路由已挂载且「按 shellId 取会话」链路接通。不启动真实服务、不占用 8000 端口、
# 不触发真实扫描（不存在的 shellId → 404）。
# ---------------------------------------------------------------------------

def test_clues_scan_route_mounted():
    from fastapi.testclient import TestClient
    from pivothub.api import api_router
    from pivothub.api.clues import router as clues_router

    # 仅在 api_router 尚未挂载 clues 时追加（避免在已接线的环境里重复注册）
    if not any(getattr(r, "path", "").endswith("/clues/scan") for r in api_router.routes):
        api_router.include_router(clues_router)

    from pivothub.app import create_app
    with TestClient(create_app()) as c:
        r = c.post("/api/clues/scan", json={"shellId": "shell-does-not-exist"})
        assert r.status_code == 404          # _get_shell 命中「Shell 不存在」契约
        assert r.json()["detail"]            # FastAPI 错误体含原因
