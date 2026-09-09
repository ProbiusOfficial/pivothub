"""数据模型 CRUD 测试（SQLAlchemy 2.x + SQLite）。"""

from __future__ import annotations

import pytest

from pivothub.db import get_session_factory, init_db, now
from pivothub.models import Credential, Flag, Host, Project, ProxyLink, Shell, TimelineEvent


@pytest.fixture(scope="module")
def db():
    init_db()
    s = get_session_factory()()
    yield s
    s.close()


def test_seed_project_exists(db):
    p = db.get(Project, "proj-1")
    assert p is not None
    assert p.name == "2026 春秋云镜 · 三层内网"
    assert p.duration_sec == 4 * 3600


def test_host_crud(db):
    h = Host(
        id="h-test-1", project_id="proj-1", ip="10.99.99.10", hostname="crud-host",
        os="Linux", layer="L2", segment="10.99.99.0/24", privilege="", owned=False,
        ports=[80], services=["http"], note="", discovery="手动登记",
    )
    db.add(h)
    db.commit()

    got = db.get(Host, "h-test-1")
    assert got is not None and got.ip == "10.99.99.10" and got.ports == [80]

    got.privilege = "root"
    got.owned = True
    db.commit()
    assert db.get(Host, "h-test-1").owned is True

    db.delete(got)
    db.commit()
    assert db.get(Host, "h-test-1") is None


def test_shell_crud_and_stable(db):
    s = Shell(
        id="s-test-1", project_id="proj-1", host_id="h-l1-01", type="PHP 一句话马",
        url="http://127.0.0.1/x.php", pwd="p", encoder="base64", alive=True,
        last_beat_at=now(), hostname="h", privilege="www-data", stable=False,
    )
    db.add(s)
    db.commit()
    got = db.get(Shell, "s-test-1")
    assert got.pwd == "p" and got.stable is False

    got.stable = True  # 终端固化落库
    db.commit()
    assert db.get(Shell, "s-test-1").stable is True

    db.delete(got)
    db.commit()


def test_proxy_link_directional_edge(db):
    l = ProxyLink(
        id="p-test-1", project_id="proj-1", tool="frp", direction="反向",
        from_host_id="h-l1-01", to_host_id="h-attacker", local_socks="127.0.0.1:10899",
        target_segment="10.99.99.0/24", status="stopped", latency=0, traffic="0 B",
        conf="frpc.ini", created_by="半自动档",
    )
    db.add(l)
    db.commit()
    got = db.get(ProxyLink, "p-test-1")
    assert got.from_host_id == "h-l1-01" and got.to_host_id == "h-attacker"
    assert got.status == "stopped"

    got.status = "alive"
    db.commit()
    assert db.get(ProxyLink, "p-test-1").status == "alive"

    db.delete(got)
    db.commit()


def test_credential_flag_timeline(db):
    c = Credential(
        id="c-test-1", project_id="proj-1", host_id="h-l1-01", username="u",
        secret="s", kind="密码", services=["ssh"], reuse=True, source="t", created_at=now(),
    )
    f = Flag(
        id="f-test-1", project_id="proj-1", host_id="h-l1-01", stage="L1 入口",
        value="flag{x}", submitted=False, created_at=now(),
    )
    t = TimelineEvent(
        id="t-test-1", project_id="proj-1", ts=now(), kind="note", title="tt", host_id=None,
    )
    db.add_all([c, f, t])
    db.commit()

    assert db.get(Credential, "c-test-1").services == ["ssh"]
    assert db.get(Flag, "f-test-1").value == "flag{x}"
    assert db.get(TimelineEvent, "t-test-1").kind == "note"

    for m, mid in ((Credential, "c-test-1"), (Flag, "f-test-1"), (TimelineEvent, "t-test-1")):
        obj = db.get(m, mid)
        db.delete(obj)
    db.commit()
    assert db.get(Credential, "c-test-1") is None
