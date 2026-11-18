from daemonsight import db
from daemonsight.collector.runner import Collector
from daemonsight.collector.sources import Source, SourceUnavailable


class FakeSource(Source):
    def __init__(self, name, results):
        self.name = name
        self.interval = 30
        self.results = list(results)

    async def collect(self):
        r = self.results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def container(name, status="running", exit_code=0, oom=False, ports=(), restarts=0, health="none"):
    return {"id": name * 8, "name": name, "image": "img:1", "project": None, "status": status,
            "exit_code": exit_code, "oom_killed": oom, "started_at": None, "finished_at": None,
            "health": health, "restart_count": restarts, "restart_policy": "no", "ports": list(ports),
            "cpu_percent": 1.0, "memory": 1024, "logs": []}


WIDE = [{"host_ip": "0.0.0.0", "host_port": 5432, "container_port": 5432, "proto": "tcp"},
        {"host_ip": "::", "host_port": 5432, "container_port": 5432, "proto": "tcp"}]


def open_rules(conn, host="testhost"):
    return sorted((r["rule"], r["key"]) for r in db.open_findings(conn, host))


def event_kinds(conn, host="testhost"):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events WHERE host=? ORDER BY id", (host,))]


async def test_findings_open_and_resolve(cfg):
    src = FakeSource("docker", [
        {"containers": [container("db", ports=WIDE), container("status", "exited", 137, oom=True)]},
        {"containers": [container("db"), container("status")]},
    ])
    col = Collector(cfg, sources=[src])
    await col.step(src)
    assert open_rules(col.conn) == [("ctr.down", "status"), ("expose.docker_bypass", "5432/tcp")]
    assert event_kinds(col.conn).count("finding_opened") == 2

    await col.step(src)
    assert open_rules(col.conn) == []
    assert event_kinds(col.conn).count("finding_resolved") == 2


async def test_failing_source_keeps_previous_data(cfg):
    src = FakeSource("docker", [
        {"containers": [container("status", "exited", 1)]},
        RuntimeError("socket timeout"),
    ])
    col = Collector(cfg, sources=[src])
    await col.step(src)
    await col.step(src)
    snap = db.get_snapshot(col.conn, "testhost", "docker")
    assert snap.ok is False
    assert "socket timeout" in snap.error
    assert snap.data["containers"][0]["name"] == "status"
    # The container finding does not flap; the source error is its own finding.
    assert open_rules(col.conn) == [("collector.source", "docker"), ("ctr.down", "status")]


async def test_unavailable_source_is_not_an_error(cfg):
    class NoDocker(Source):
        name = "docker"
        interval = 30

        async def collect(self):
            raise SourceUnavailable("no Docker socket")

    src = NoDocker()
    col = Collector(cfg, sources=[src])
    await col.step(src)
    snap = db.get_snapshot(col.conn, "testhost", "docker")
    assert snap.ok is True
    assert snap.data == {"available": False, "reason": "no Docker socket"}
    assert open_rules(col.conn) == []


def listener(port, proto="tcp", scope="all", addresses=("0.0.0.0",)):
    return {"proto": proto, "port": port, "addresses": list(addresses), "pid": None, "process": "x",
            "owner": {"kind": "unknown", "id": None}, "scope": scope}


async def test_port_and_restart_events(cfg):
    ports = FakeSource("ports", [
        {"listeners": [listener(22)], "owners_known": True},
        {"listeners": [listener(22), listener(5432), listener(8080, scope="loopback", addresses=("127.0.0.1",)),
                       listener(45000, proto="udp")], "owners_known": True},
    ])
    unit = {"name": "web.service", "description": "", "load": "loaded", "active": "active", "sub": "running",
            "path": "/", "since": None, "memory": None, "cpu_ns": None, "main_pid": None, "result": "success",
            "cgroup": None}
    systemd = FakeSource("systemd", [
        {"units": [{**unit, "restarts": 1}], "counts": {"active": 1}},
        {"units": [{**unit, "restarts": 2}], "counts": {"active": 1}},
    ])
    col = Collector(cfg, sources=[ports, systemd])
    col.eph = (32768, 60999)
    for s in (ports, systemd, ports, systemd):
        await col.step(s)
    titles = [r["title"] for r in db.recent_events(col.conn, "testhost", 20)]
    assert "New listener 5432/tcp" in titles
    assert "web.service restarted" in titles
    assert not any("8080" in t or "45000" in t for t in titles)


async def test_failed_unit_finding(cfg):
    systemd = FakeSource("systemd", [{"units": [{
        "name": "backup.service", "description": "", "load": "loaded", "active": "failed", "sub": "failed",
        "path": "/", "since": None, "restarts": 0, "memory": None, "cpu_ns": None, "main_pid": None,
        "result": "exit-code", "cgroup": None}], "counts": {"failed": 1}}])
    col = Collector(cfg, sources=[systemd])
    await col.step(systemd)
    rows = db.open_findings(col.conn, "testhost")
    assert [(r["rule"], r["severity"]) for r in rows] == [("svc.failed", "high")]
    assert "journalctl -u backup.service" in rows[0]["detail"]


async def test_reader_opens_while_writer_holds_wal(cfg):
    src = FakeSource("docker", [{"containers": []}])
    col = Collector(cfg, sources=[src])
    await col.step(src)
    reader = db.connect_reader(cfg.db_path)
    assert db.get_snapshot(reader, "testhost", "docker").data == {"containers": []}
    reader.close()


def test_proc_info_details_for_current_process():
    import os
    from daemonsight.collector.sources.ports import _proc_info
    info = _proc_info(os.getpid())
    assert info["cmdline"] and info["user"] and info["started"] and info["exe"]


def test_proc_info_masks_secrets_and_truncates(monkeypatch):
    import psutil
    from daemonsight.collector.sources import ports

    class P:
        def __init__(self, pid): pass
        def name(self): return "app"
        def cmdline(self): return ["app", "--password=hunter2", "x" * 500]
        def exe(self): raise psutil.AccessDenied()
        def username(self): return "svc"
        def create_time(self): return 1.0

    monkeypatch.setattr(ports.psutil, "Process", P)
    info = ports._proc_info(1)
    assert "hunter2" not in info["cmdline"] and len(info["cmdline"]) == 401 and info["cmdline"].endswith("…")
    assert info["exe"] is None and info["user"] == "svc"
