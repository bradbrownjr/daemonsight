#!/usr/bin/env python3
"""Make the README screenshots (docs/images/*.png) from sample data.

    python scripts/screenshots.py [--out docs/images]

Starts the web app in this process as a hub (uvicorn on 127.0.0.1, a free port) with a temporary data
directory, fills it with made-up hosts, and photographs it with Playwright's Chromium in the dark theme.
Needs `pip install -e .[screenshots]` and `playwright install chromium`.

Development only. It borrows the fakes and sample data from tests/ (fake Unraid, OPNsense, Docker reader and
CrowdSec, the CVE feed samples) instead of copying them, so the screenshots and the tests describe the same
servers. Nothing here ships in the package. Everything shown is invented: example.com and the documentation
address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

Same input, same files: the clock (time.time and today's date) is frozen, the version string is fixed, animations
are off, and PNGs are saved without metadata. The fonts come from the machine, so a different machine can
draw slightly different text; the screenshots workflow runs on one image of GitHub's runners for that reason.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 2026-11-24 12:00:00 UTC, a Tuesday. Every "ago" on the pages counts back from here.
NOW = dt.datetime(2026, 11, 24, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp()
PASSWORD = "sample-password-123"
TOKEN = "r" * 24 + "0123456789abcdef"


def freeze_clock() -> None:
    """time.time() and date.today() answer the same instant for the whole run. Monotonic clocks stay real, so
    timeouts and the event loop work as usual."""
    time.time = lambda: NOW  # type: ignore[assignment]

    class FrozenDate(dt.date):
        @classmethod
        def today(cls):
            return cls(2026, 11, 24)

    from daemonsight import distro, findings
    from daemonsight.remote import docker_images
    for mod in (distro, findings, docker_images):
        mod.date = FrozenDate


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- sample data ------------------------------------------------------------

def put_host(conn, hub, host, address, snaps, *, metrics=None, events=(), version="0.1.0", exposure=(), role=None):
    """One collector host: its snapshots, a short history and the findings its own rules give."""
    from daemonsight import db, findings
    from daemonsight.config import Config

    hub.add_host(conn, host)
    conn.execute("UPDATE hosts SET last_seen=?, last_sent_at=?, max_interval=60, version=?, address=?, last_seq=1 WHERE id=?",
                 (NOW - 20, NOW - 20, version, address, host))
    for source, data in snaps.items():
        if source == "systemd":
            data["counts"] = counts(data["units"])
        db.put_snapshot(conn, host, source, NOW - 25, True, None, data)
    cfg = Config(host_id=host)
    cfg.exposure.expected_public = list(exposure)
    if role:
        cfg.role = role
    for ts, values in (metrics or []):
        db.add_metrics(conn, host, ts, values)
    for ago, kind, title, sev, detail, link in events:
        db.add_event(conn, host, NOW - ago, kind, title, severity=sev, detail=detail, link=link)
    stored = db.get_snapshots(conn, host)
    db.reconcile_findings(conn, host, NOW - 20, findings.evaluate(stored, cfg, {"mem_avg": None, "eph": (32768, 60999)}))
    if role:  # the hub reads the role from the host's uploaded settings
        db.put_snapshot(conn, host, "settings", NOW - 20, True, None, {"role": role, "exposure": {"expected_public": list(exposure)}})


def series(base, wobble, n=48, step=300):
    """Deterministic, gently moving history ending at NOW."""
    return [(NOW - (n - i) * step, base + wobble[i % len(wobble)]) for i in range(n)]


def system_snap(os_name, osr, kernel, virt, up_days, cpu, mem, mem_total_gb, disks, nic="eth0"):
    from daemonsight import distro
    return {"os": os_name, **distro.os_ident(osr), "kernel": kernel, "virt": virt, "boot_time": NOW - up_days * 86400,
            "cpu": {"percent": cpu, "count": 4, "load": [0.42, 0.37, 0.30]},
            "memory": {"total": mem_total_gb * 2**30, "available": int(mem_total_gb * 2**30 * (100 - mem) / 100), "percent": mem,
                       "swap_total": 2 * 2**30, "swap_used": 120 * 2**20},
            "disks": [{"mount": m, "device": d, "fstype": "ext4", "total": t * 1e9, "used": t * 1e9 * p / 100, "percent": p}
                      for m, d, t, p in disks],
            "net": {nic: {"rx_bps": 1.8e6, "tx_bps": 6.2e5}}}


def unit(name, desc, active="active", sub="running", result="success", restarts=0, since_days=12, memory=60 * 2**20):
    return {"name": name, "description": desc, "load": "loaded", "active": active, "sub": sub, "path": "/",
            "since": NOW - since_days * 86400, "restarts": restarts, "memory": memory, "cpu_ns": 4_000_000_000,
            "main_pid": 1000, "result": result, "cgroup": None}


def listener(port, unit_name=None, process=None, scope="all", addresses=("0.0.0.0",), proto="tcp"):
    owner = {"kind": "unit", "id": unit_name} if unit_name else {"kind": "unknown", "id": None}
    return {"proto": proto, "port": port, "addresses": list(addresses), "scope": scope, "pid": 1, "process": process, "owner": owner}


def ctr(name, image, status="running", exit_code=0, ports=(), restarts=0, cpu=1.2, memory=80 * 2**20, project="stack"):
    return {"id": (name * 8)[:12], "name": name, "image": image, "project": project, "status": status, "exit_code": exit_code,
            "oom_killed": False, "started_at": NOW - 9 * 86400, "finished_at": None, "health": "none", "restart_count": restarts,
            "restart_policy": "unless-stopped", "ports": list(ports), "cpu_percent": cpu, "memory": memory, "logs": []}


def upd(name, cur, cand, security=False):
    return {"name": name, "current": cur, "candidate": cand, "arch": "amd64", "security": security,
            "origin": "Debian-Security:13/stable-security" if security else "Debian:13.7/stable"}


def apt_data(updates, reboot=False, kernel=None):
    return {"available": True, "backend": "apt", "updates": updates, "security_count": sum(1 for u in updates if u["security"]),
            "kept_back": [], "removals": 0, "held": [], "lists_age": NOW - 5 * 3600, "daily_timer": "enabled",
            "reboot": {"required": reboot, "pkgs": ["linux-image-amd64"] if reboot else []},
            "kernel": kernel or {"managed": False}, "needrestart": {"installed": False}, "unattended_upgrades": True,
            "auto_updates": {"tool": "unattended-upgrades", "installed": True, "lists": "1", "unattended": "1", "timer": "enabled",
                             "on": True, "known": True},
            "errors": {}}


IPTABLES = """\
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
"""


def counts(units):
    out: dict[str, int] = {}
    for u in units:
        out[u["active"]] = out.get(u["active"], 0) + 1
    return out


def web01_images():
    """What the hub stores of web-01's container images (hub.merge_docker_images): `app` (Debian 12, behind the host's Caddy site) and
    `db` (Debian 13, published on all interfaces), and the stopped `worker`."""
    from daemonsight import hub
    from tests.fake_docker import hid
    from tests.test_docker_images import BOOKWORM_PACKAGES, DEB12, entry, os_
    from daemonsight import docker_packages as pk

    def wire(e):
        e = dict(e)
        if e["manager"]:
            e["hash"] = pk.fingerprint(e)
        return e
    app, dbi, worker = hid("web01-app"), hid("web01-db"), hid("web01-worker")
    entries = [wire(entry(app, DEB12, BOOKWORM_PACKAGES, container="app", read_at=int(NOW - 3000))),
               wire(entry(dbi, os_("debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)"), [("libc-ares2", "c-ares", "1.10.0-1", ""), ("bash", "", "5.2.37-2", "")],
                          container="db", read_at=int(NOW - 3000))),
               wire(entry(worker, DEB12, None, error="not read: stopped", container=None, read_at=None))]
    up = hub.DockerImagesIn.model_validate({
        "v": 1, "taken_at": NOW - 25, "engine": {"version": "29.0.0", "api": "1.54"},
        "containers": [{"name": "app", "image": "example/app:2.4", "image_id": app, "state": "running"},
                       {"name": "db", "image": "postgres:17", "image_id": dbi, "state": "running"},
                       {"name": "worker", "image": "example/worker:2.4", "image_id": worker, "state": "exited"}],
        "images": [{"id": app, "tags": ["example/app:2.4"]}, {"id": dbi, "tags": ["postgres:17"]}, {"id": worker, "tags": ["example/worker:2.4"]}],
        "image_packages": entries})
    return hub.merge_docker_images(up, None)[0]


def seed_collectors(conn):
    from daemonsight import hub
    from daemonsight.collector.sources.caddy import parse_config
    from daemonsight.collector.sources.firewall import parse_iptables_save, summarize_parts
    from tests.test_phase2 import adapter_json

    deb13 = {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"}
    caddy = parse_config(adapter_json("portless_upstream"))
    caddy["upstream_status"] = [{"address": "app:80", "num_requests": 3, "fails": 0}]
    caddy["admin_address"] = "localhost:2019"
    wide = [{"host_ip": "0.0.0.0", "host_port": 5432, "container_port": 5432, "proto": "tcp"},
            {"host_ip": "::", "host_port": 5432, "container_port": 5432, "proto": "tcp"}]
    web01 = {
        "system": system_snap("Debian GNU/Linux 13 (trixie)", deb13, "6.12.48+deb13-amd64", "kvm", 41, 23.0, 62.0, 4,
                              [("/", "/dev/vda1", 58, 71.0)], "ens3"),
        "systemd": {"units": [unit("caddy.service", "Caddy web server"), unit("ssh.service", "OpenBSD Secure Shell server"),
                              unit("docker.service", "Docker Application Container Engine"),
                              unit("fail2ban.service", "Fail2Ban Service"),
                              unit("backup.service", "Nightly backup", active="failed", sub="failed", result="exit-code", since_days=0)]},
        "ports": {"listeners": [listener(22, "ssh.service", "sshd"), listener(80, "caddy.service", "caddy"),
                                listener(443, "caddy.service", "caddy"), listener(5432, process="docker-proxy"),
                                listener(2019, "caddy.service", "caddy", "loopback", ("127.0.0.1",))],
                  "owners_known": True,
                  "addresses": [{"nic": "ens3", "ip": "203.0.113.10", "scope": "public"}]},
        "docker": {"version": {"Version": "29.0.0"},
                   "containers": [ctr("app", "example/app:2.4"), ctr("db", "postgres:17", ports=wide, memory=210 * 2**20),
                                  ctr("worker", "example/worker:2.4", status="exited", exit_code=1, restarts=3)]},
        "caddy": caddy,
        "docker_images": web01_images(),
        "fail2ban": {"version": "1.1.0", "jails": [{
            "name": "sshd", "backend": "systemd", "logpaths": [], "journalmatch": ["_SYSTEMD_UNIT=ssh.service"], "units": ["ssh.service"],
            "failed_now": 2, "failed_total": 311, "banned_now": 2, "banned_total": 57,
            "bans": [{"ip": "198.51.100.23", "banned_at": "2026-11-24 09:41:12", "seconds": 600, "until": None},
                     {"ip": "203.0.113.77", "banned_at": "2026-11-24 10:02:55", "seconds": 600, "until": None}],
            "bantime": 600, "findtime": 600, "maxretry": 5, "ignoreip": [], "actions": ["nftables"]}]},
        "firewall": summarize_parts([parse_iptables_save(IPTABLES, "ip")], "iptables-save"),
        "packages": apt_data([upd("libssl3t64", "3.5.1-1", "3.5.4-1~deb13u1", True), upd("curl", "8.14.1-2", "8.14.1-3", True),
                              upd("tzdata", "2025b-5", "2025c-0+deb13u1"), upd("openssh-server", "1:10.0p1-5", "1:10.0p1-7")],
                             reboot=True),
    }
    put_host(conn, hub, "web-01", "203.0.113.10", web01, exposure=["22/tcp", "80/tcp", "443/tcp"],
             metrics=[(ts, {"cpu.percent": v}) for ts, v in series(22, [0, 6, -4, 9, 2, -7])]
             + [(ts, {"mem.percent": v}) for ts, v in series(60, [0, 1, 2, 1, 0, -1])],
             events=[(1800, "pkg_security", "2 new security updates", "medium", "libssl3t64, curl", "/packages#security"),
                     (5400, "ctr_stopped", "Container worker exited", "high", "Exit code 1", "/services#ctr-worker"),
                     (9000, "ban", "sshd banned 1 address", None, None, "/fail2ban#jail-sshd")])

    mail = {
        "system": system_snap("Debian GNU/Linux 12 (bookworm)", {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"},
                              "6.8.12-4-pve", "lxc", 96, 4.0, 38.0, 2, [("/", "/dev/mapper/root", 16, 34.0)]),
        "systemd": {"units": [unit("postfix@-.service", "Postfix Mail Transport Agent"), unit("dovecot.service", "Dovecot IMAP server"),
                              unit("ssh.service", "OpenBSD Secure Shell server")], },
        "ports": {"listeners": [listener(22, "ssh.service", "sshd"), listener(25, "postfix@-.service", "master"),
                                listener(993, "dovecot.service", "dovecot")], "owners_known": True,
                  "addresses": [{"nic": "eth0", "ip": "192.0.2.25", "scope": "private"}]},
        "packages": apt_data([upd("bash", "5.2.15-2", "5.2.15-2+b8")]),
    }
    put_host(conn, hub, "mail", "192.0.2.25", mail, metrics=[(ts, {"cpu.percent": v}) for ts, v in series(4, [0, 1, -1])])

    fedora = {
        "system": system_snap("Fedora Linux 44 (Workstation Edition)", {"ID": "fedora", "VERSION_ID": "44"}, "6.19.8-200.fc44.x86_64",
                              None, 9, 11.0, 47.0, 32, [("/", "/dev/nvme0n1p3", 930, 42.0)], "enp5s0"),
        "systemd": {"units": [unit("sshd.service", "OpenSSH server daemon"), unit("firewalld.service", "firewalld")], },
        "ports": {"listeners": [listener(22, "sshd.service", "sshd")], "owners_known": True,
                  "addresses": [{"nic": "enp5s0", "ip": "192.0.2.40", "scope": "private"}]},
        "packages": {"available": True, "backend": "dnf", "updates": [{"name": "kernel-core", "current": "6.19.8-200.fc44", "candidate": "6.19.10-200.fc44",
                                                                        "arch": "x86_64", "security": True, "origin": "updates"}],
                     "security_count": 1, "kept_back": [], "removals": 0, "held": [], "lists_age": NOW - 3600, "daily_timer": "enabled",
                     "reboot": {"required": False, "pkgs": []}, "kernel": {"managed": False}, "needrestart": {"installed": False},
                     "auto_updates": {"tool": "dnf5-automatic", "installed": True, "timer": "enabled", "apply": True,
                                      "upgrade_type": "default", "on": True, "known": True}, "errors": {}},
    }
    put_host(conn, hub, "workstation", "192.0.2.40", fedora, role="workstation",
             metrics=[(ts, {"cpu.percent": v}) for ts, v in series(10, [0, 3, -2, 5])])


def seed_remotes(conn, cfg, workdir):
    """The Unraid server (containers, Docker reader, images, CVE rows) and the OPNsense firewall with CrowdSec."""
    import httpx
    from daemonsight.cve import feeds, match, store as cvestore
    from daemonsight.remote import docker_images as di, poll, store
    from tests.fake_crowdsec import FakeLapi, KEY as CSKEY, decision
    from tests.fake_docker import FakeReader, IDS, hid, standard_summary
    from tests.fake_opnsense import FakeOpnsense, KEY as OKEY, SECRET as OSECRET
    from tests.fake_unraid import FakeUnraid, KEY as UKEY
    from tests.test_cve import epss_gz, kev_gz, tracker_gz
    from tests.test_docker_images import BOOKWORM_PACKAGES, DEB12, entry, os_

    raw = standard_summary()
    extra = [("hedgedoc", "node-app", os_("debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)"), [("libc-ares2", "c-ares", "1.10.0-1", "")], "dpkg"),
             ("legacy-cms", "old-debian", os_("debian", "10", "buster", "Debian GNU/Linux 10 (buster)"), [("bash", "", "5.0-4", "")], "dpkg"),
             ("tiny-proxy", "alpine-new", os_("alpine", "3.22.1", "", "Alpine Linux v3.22"), [("musl", "", "1.2.5-r10", "")], "apk"),
             ("media", "ubuntu-new", os_("ubuntu", "24.04", "noble", "Ubuntu 24.04.1 LTS", ["debian"]), [("bash", "", "5.2.21-2", "")], "dpkg"),
             ("scratch-app", "distroless", DEB12, None, None),
             ("bullseye-app", "bullseye", os_("debian", "11", "bullseye", "Debian GNU/Linux 11 (bullseye)"), [("bash", "", "5.1-2", "")], "dpkg")]
    entries = [entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web"),
               entry(IDS["postgres"], os_("ubuntu", "22.04", "jammy", "Ubuntu 22.04.4 LTS", ["debian"]), BOOKWORM_PACKAGES, container="db"),
               entry(IDS["widget-new"], os_("alpine", "3.17.2", "", "Alpine Linux v3.17"), [("musl", "", "1.2.3-r4", "")], manager="apk", container="widget"),
               entry(IDS["inuse2"], DEB12, None, error="not read: stopped", container=None, read_at=None)]
    for cname, iname, o, pk, mgr in extra:
        iid = hid(iname)
        raw["containers"].append({"name": cname, "image": f"example/{iname}:1", "image_id": iid, "state": "running"})
        raw["images"].append({"id": iid, "tags": [f"example/{iname}:1"], "digests": [], "created": 1_700_000_000, "size": 60_000_000,
                              "last_tag": None, "labels": {}, "in_use": True})
        entries.append(entry(iid, o, pk, manager=mgr, container=cname,
                             **({"error": "packages not read: no dpkg or apk package database in the image (a distroless or minimal image)"} if iname == "distroless" else {})))
    raw["image_packages"] = entries
    reader = FakeReader(TOKEN, raw)

    cdb = cvestore.connect(cfg.cve_db_path)
    feeds.load_debian(cdb, tracker_gz(workdir), {"bookworm", "trixie", "buster", "bullseye"})
    feeds.load_epss(cdb, epss_gz(workdir))
    feeds.load_kev(cdb, kev_gz(workdir))
    for name, f in feeds.FEEDS.items():
        feeds.feed_row(cdb, f)
        feeds._record(cdb, f, checked_at=NOW, ok_at=NOW - 3600, changed_at=NOW, status="ok", rows=3, size=1000, note="")
    for ph, inv in di.image_inventories({"tower": {"image_packages": entries}, "web-01": web01_images()}).items():
        match.match_host(cdb, ph, inv, "g")
    cdb.close()
    from daemonsight.cve import run as cve_run
    asyncio.run(cve_run.Chore(cfg, conn, None)._docker_findings(NOW - 10))     # web-01's image findings, as the CVE chore raises them

    unraid, firewall, lapi = FakeUnraid(), FakeOpnsense(), FakeLapi()
    lapi.decisions = [decision("192.0.2.10", id_=1),
                      decision("203.0.113.40", scenario="crowdsecurity/ssh-bf", id_=2),
                      decision("203.0.113.41", scenario="crowdsecurity/ssh-bf", id_=3),
                      decision("203.0.113.42", scenario="crowdsecurity/http-probing", id_=4)]
    net = lapi.attach(unraid.net())
    net.reader = reader.client

    def http(tls="verify", pem=None):
        def handler(request):
            return (firewall if request.url.host.startswith("firewall") else unraid).handler(request)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5, follow_redirects=False)
    net.http = http

    conn_w = conn
    store.add(conn_w, cfg.data_dir, "tower", "unraid", "https://tower.example.com:4443", UKEY, interval=60, now=NOW - 100,
              reader_url="http://daemonsight-docker-reader:8467", reader_token=TOKEN)
    store.add(conn_w, cfg.data_dir, "firewall", "opnsense", "https://firewall.example.com:8443", OKEY, secret=OSECRET, interval=60,
              now=NOW - 100, crowdsec_url="http://192.0.2.1:8180", crowdsec_key=CSKEY,
              crowdsec_never=["203.0.113.50", "198.51.100.128/25"])
    asyncio.run(poll.run_once(conn_w, cfg, net, NOW))
    # The firewall's pending update (26.1.2_3 to 26.1.5): the real changelog files in tests/fixtures, as the CVE chore would load them.
    from daemonsight.cve import opnsense as chg
    from tests import fake_changelog
    cdb = cvestore.connect(cfg.cve_db_path)
    chg.load(cdb, fake_changelog.write_tarball(workdir / "changelog.tar.gz"), {"26.1"})
    chg.match_host(cdb, chg.pseudo_host("firewall"), {"installed": "26.1.2_3", "offered": "26.1.5"}, "g")
    feeds.feed_row(cdb, feeds.OPNSENSE_FEED)
    feeds._record(cdb, feeds.OPNSENSE_FEED, checked_at=NOW, ok_at=NOW - 3600, changed_at=NOW, status="ok", rows=3, size=1000, note="")
    cdb.close()
    asyncio.run(poll.run_once(conn_w, cfg, net, NOW + 700))
    return net


def build_hub(workdir: Path):
    import daemonsight.web.app as webapp
    from daemonsight import db, hub
    from daemonsight.config import Config
    from daemonsight.web.auth import hash_password

    cfg = Config(host_id="hub", data_dir=str(workdir / "data"))
    cfg.hub.enabled = True
    cfg.cve.enabled = True
    cfg.web.password_file = str(workdir / "pw")
    cfg.web.secret_file = str(workdir / "secret")
    cfg.web.listen = "127.0.0.1"
    (workdir / "pw").write_text(hash_password(PASSWORD))
    (workdir / "secret").write_text("s" * 64)
    conn = db.connect_writer(cfg.db_path)
    seed_collectors(conn)
    net = seed_remotes(conn, cfg, workdir)
    conn.close()
    webapp.full_version = lambda: "0.1.0"
    return webapp.create_app(cfg, remote_net=net)


def serve(app) -> tuple[str, "object"]:
    import uvicorn
    port = free_port()
    # lifespan off: no background chores (feed downloads, polling) while the pictures are taken.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("the web app did not start")
    return f"http://127.0.0.1:{port}", server


# --- pictures ---------------------------------------------------------------

FREEZE_CSS = "*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important;scroll-behavior:auto!important}"


def settle(page):
    page.add_style_tag(content=FREEZE_CSS)
    page.wait_for_load_state("networkidle")
    page.evaluate("document.fonts.ready")
    page.evaluate("document.activeElement && document.activeElement.blur()")
    page.wait_for_timeout(200)


def login(page, base):
    page.goto(base + "/login")
    page.fill("input[name=password]", PASSWORD)
    page.press("input[name=password]", "Enter")
    page.wait_for_load_state("networkidle")


def cut_at(page, limit, floor, selector):
    """The lowest bottom edge of a card or table row that is at or above `limit` (and below `floor`), so the
    picture never ends in the middle of one. Eight pixels are added below it."""
    bottoms = page.evaluate("(sel) => [...document.querySelectorAll(sel)].map(e => e.getBoundingClientRect().bottom + window.scrollY)", selector)
    fits = [b for b in bottoms if floor <= b <= limit - 8]
    return int(max(fits) + 8) if fits else limit


def shoot(page, url, path, *, limit, floor=400, selector="tbody tr, section.card"):
    page.goto(url)
    settle(page)
    page.evaluate("window.scrollTo(0, 0)")
    height = cut_at(page, limit, floor, selector)
    page.screenshot(path=str(path), full_page=True, clip={"x": 0, "y": 0, "width": page.viewport_size["width"], "height": height})


def optimise(path: Path) -> None:
    """Re-save as an 8-bit palette PNG with no metadata. Pillow only; skipped if it is not installed."""
    try:
        from PIL import Image
    except ImportError:
        return
    img = Image.open(path).convert("RGB")
    img.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)


def take(base: str, out: Path) -> None:
    from playwright.sync_api import sync_playwright

    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        opts = dict(color_scheme="dark", reduced_motion="reduce", locale="en-US", timezone_id="UTC", device_scale_factor=1, bypass_csp=True)
        ctx = browser.new_context(viewport={"width": 1400, "height": 900}, **opts)
        ctx.add_cookies([{"name": "theme", "value": "dark", "url": base}])
        page = ctx.new_page()
        login(page, base)
        shoot(page, base + "/", out / "hosts.png", limit=900)
        shoot(page, base + "/h/web-01/", out / "overview.png", limit=960, selector="section.card, .list-group-item")
        shoot(page, base + "/h/tower/images", out / "unraid-images.png", limit=960)
        shoot(page, base + "/h/web-01/images", out / "collector-images.png", limit=960)
        ctx.close()

        ctx = browser.new_context(viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True, **opts)
        ctx.add_cookies([{"name": "theme", "value": "dark", "url": base}])
        page = ctx.new_page()
        login(page, base)
        page.goto(base + "/h/web-01/")
        settle(page)
        page.locator("#ds-menu-btn").first.click()
        page.wait_for_timeout(300)
        page.screenshot(path=str(out / "phone.png"))
        page.goto(base + "/h/web-01/images")
        settle(page)
        page.screenshot(path=str(out / "collector-images-phone.png"), full_page=True)
        ctx.close()
        browser.close()
    for f in sorted(out.glob("*.png")):
        optimise(f)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(ROOT / "docs" / "images"), help="where the PNGs go (default docs/images)")
    args = ap.parse_args()
    freeze_clock()
    with tempfile.TemporaryDirectory(prefix="daemonsight-shots-") as tmp:
        app = build_hub(Path(tmp))
        base, server = serve(app)
        try:
            take(base, Path(args.out))
        finally:
            server.should_exit = True
    for f in sorted(Path(args.out).glob("*.png")):
        print(f"{f}  {f.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
