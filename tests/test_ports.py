import socket
from collections import namedtuple

import psutil

from daemonsight.collector.sources.ports import classify, group_listeners, owner_from_cgroup

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")
CID = "f" * 64


def test_owner_systemd_unit():
    assert owner_from_cgroup("0::/system.slice/ssh.service\n") == {"kind": "unit", "id": "ssh.service"}


def test_owner_container_systemd_driver():
    assert owner_from_cgroup(f"0::/system.slice/docker-{CID}.scope\n") == {"kind": "container", "id": CID}


def test_owner_container_cgroupfs_driver():
    assert owner_from_cgroup(f"0::/docker/{CID}\n") == {"kind": "container", "id": CID}


def test_owner_session_and_init():
    assert owner_from_cgroup("0::/user.slice/user-1000.slice/session-c57.scope")["kind"] == "session"
    assert owner_from_cgroup("0::/init.scope")["kind"] == "init"


def test_classify():
    assert classify("0.0.0.0") == "all"
    assert classify("::") == "all"
    assert classify("127.0.0.1") == "loopback"
    assert classify("::1") == "loopback"
    assert classify("10.6.26.3") == "private"
    assert classify("fe80::1%eth0") == "private"
    assert classify("8.8.8.8") == "public"


def fake_lookup(pid):
    return {"pid": pid, "process": f"proc{pid}", "owner": {"kind": "unit", "id": f"svc{pid}.service"}}


def test_group_listeners_merges_addresses_and_skips_clients():
    conns = [
        Conn(3, socket.AF_INET, socket.SOCK_STREAM, Addr("0.0.0.0", 22), (), psutil.CONN_LISTEN, 10),
        Conn(4, socket.AF_INET6, socket.SOCK_STREAM, Addr("::", 22), (), psutil.CONN_LISTEN, 10),
        Conn(5, socket.AF_INET, socket.SOCK_STREAM, Addr("10.0.0.5", 22), Addr("10.0.0.9", 5555),
             psutil.CONN_ESTABLISHED, 10),
        Conn(6, socket.AF_INET, socket.SOCK_STREAM, Addr("127.0.0.1", 2019), (), psutil.CONN_LISTEN, 20),
        Conn(7, socket.AF_INET, socket.SOCK_DGRAM, Addr("0.0.0.0", 51820), (), psutil.CONN_NONE, None),
        Conn(8, socket.AF_INET, socket.SOCK_DGRAM, Addr("10.0.0.5", 40000), Addr("1.1.1.1", 53),
             psutil.CONN_NONE, 30),
    ]
    rows = group_listeners(conns, proc_lookup=fake_lookup)
    by_port = {(r["proto"], r["port"]): r for r in rows}
    assert set(by_port) == {("tcp", 22), ("tcp", 2019), ("udp", 51820)}
    assert by_port[("tcp", 22)]["addresses"] == ["0.0.0.0", "::"]
    assert by_port[("tcp", 22)]["scope"] == "all"
    assert by_port[("tcp", 22)]["owner"]["id"] == "svc10.service"
    assert by_port[("tcp", 2019)]["scope"] == "loopback"
    assert by_port[("udp", 51820)]["pid"] is None
    # Widest exposure first.
    assert rows[-1]["port"] == 2019
