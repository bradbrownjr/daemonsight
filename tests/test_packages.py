"""The packages source (apt updates, reboots, old libraries), its rules and page."""

import time

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, findings
from daemonsight.collector import runner
from daemonsight.collector.sources import SourceUnavailable, packages as pk
from daemonsight.config import Config
from daemonsight.db import Snapshot
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_provenance import check_panels

# The Inst/Conf line formats are real `apt-get -s -o Debug::NoLocking=1 install` output
# (Debian 13: a reinstall of libssl3t64 from Debian-Security, a new package cowsay from
# Debian). This host had nothing pending, so the upgrade lines with an old version, the
# kept-back block and the Remv line are hand-written in the same format.
DIST_UPGRADE = """\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages have been kept back:
  linux-image-amd64 linux-headers-amd64
The following packages will be upgraded:
  libssl3t64 curl
2 upgraded, 1 newly installed, 1 to remove and 2 not upgraded.
Inst libssl3t64 [3.5.1-1] (3.5.4-1~deb13u1 Debian-Security:13/stable-security [amd64])
Inst curl [8.14.1-2+deb13u7] (8.14.1-2+deb13u8 Debian-Security:13/stable-security, Debian:13.7/stable [amd64])
Inst cowsay (3.03+dfsg2-8 Debian:13.7/stable [all])
Inst tzdata [2025b-5] (2025c-0+deb13u1 Debian:13.7/stable [all])
Remv oldlib [1.0]
Conf libssl3t64 (3.5.4-1~deb13u1 Debian-Security:13/stable-security [amd64])
Conf cowsay (3.03+dfsg2-8 Debian:13.7/stable [all])
"""

NEEDRESTART = """\
NEEDRESTART-VER: 3.8
NEEDRESTART-KCUR: 6.12.48+deb13-amd64
NEEDRESTART-KEXP: 6.12.57+deb13-amd64
NEEDRESTART-KSTA: 3
NEEDRESTART-SVC: cron.service
NEEDRESTART-SVC: ssh.service
NEEDRESTART-SESS: root @ session #4
"""

KERNELS = "linux-image-6.12.48+deb13-amd64\t6.12.48-1\tii \nlinux-image-6.12.57+deb13-amd64\t6.12.57-1\tii \n" \
          "linux-image-amd64\t6.12.57-1\tii \nlinux-image-6.1.0-old\t6.1.0-1\trc \n"


def snap(data, taken_at=None):
    return Snapshot("packages", taken_at if taken_at is not None else time.time(), True, None, data)


def data(**kw):
    base = {"available": True, "updates": [], "security_count": 0, "kept_back": [], "removals": 0, "held": [],
            "lists_age": time.time() - 3600, "daily_timer": "enabled", "reboot": {"required": False, "pkgs": []},
            "kernel": {"managed": False, "running": "6.1.0"}, "needrestart": {"installed": False},
            "unattended_upgrades": False, "errors": {}}
    base.update(kw)
    return base


def upd(name, security=False, current="1.0"):
    return {"name": name, "current": current, "candidate": "1.1", "origin": "Debian:13/stable", "arch": "amd64",
            "security": security}


# ---- parsing ----------------------------------------------------------------

def test_parse_dist_upgrade():
    r = pk.parse_dist_upgrade(DIST_UPGRADE)
    by = {u["name"]: u for u in r["updates"]}
    assert set(by) == {"libssl3t64", "curl", "cowsay", "tzdata"}
    assert by["libssl3t64"] == {"name": "libssl3t64", "current": "3.5.1-1", "candidate": "3.5.4-1~deb13u1",
                                "origin": "Debian-Security:13/stable-security", "arch": "amd64", "security": True}
    assert by["cowsay"]["current"] is None and by["cowsay"]["arch"] == "all" and not by["cowsay"]["security"]
    assert by["curl"]["security"] and "Debian:13.7/stable" in by["curl"]["origin"]  # two origins
    assert not by["tzdata"]["security"]
    assert r["kept_back"] == ["linux-headers-amd64", "linux-image-amd64"]
    assert r["removals"] == 1


def test_parse_nothing_pending():
    assert pk.parse_dist_upgrade("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n") == \
        {"updates": [], "kept_back": [], "removals": 0}


def test_is_security():
    assert pk.is_security("Debian-Security:13/stable-security")
    assert pk.is_security("Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security")
    assert not pk.is_security("Debian:13.7/stable") and not pk.is_security(None)


def test_kernel_managed_and_newer():
    pkgs = pk.parse_kernel_packages(KERNELS)
    assert len(pkgs) == 3  # the "rc" line is dropped
    gt = lambda a, b: [int(x) for x in a.replace("-", ".").split(".")] > [int(x) for x in b.replace("-", ".").split(".")]
    assert pk.kernel_state("6.12.48+deb13-amd64", pkgs, gt) == \
        {"managed": True, "running": "6.12.48+deb13-amd64", "newer_installed": "6.12.57+deb13-amd64"}
    assert pk.kernel_state("6.12.57+deb13-amd64", pkgs, gt)["newer_installed"] is None


def test_kernel_unmanaged_in_container():
    pkgs = pk.parse_kernel_packages(KERNELS)
    assert pk.kernel_state("6.18.38-Unraid", pkgs) == {"managed": False, "running": "6.18.38-Unraid"}
    assert pk.kernel_state("6.18.38-Unraid", []) == {"managed": False, "running": "6.18.38-Unraid"}


def test_parse_needrestart():
    r = pk.parse_needrestart(NEEDRESTART)
    assert r == {"installed": True, "services": ["cron.service", "ssh.service"], "ksta": 3,
                 "kcur": "6.12.48+deb13-amd64", "kexp": "6.12.57+deb13-amd64"}


def test_version_gt_uses_dpkg():
    assert pk.version_gt("2:1.0-1", "1:9.9-1") and not pk.version_gt("1.0~rc1", "1.0")


async def test_unavailable_without_apt(monkeypatch):
    monkeypatch.setattr(pk.shutil, "which", lambda name: None)
    with pytest.raises(SourceUnavailable):
        await pk.PackagesSource(3600).collect()
    assert await runner.collect_once(pk.PackagesSource(3600), 5) == \
        (True, None, {"available": False, "reason": "This host uses neither apt and dpkg nor dnf and rpm"})


def test_parts_fail_independently(monkeypatch):
    monkeypatch.setattr(pk.shutil, "which", lambda name: f"/usr/bin/{name}" if name != "needrestart" else None)

    def fake_run(argv):
        if argv[0] == "apt-get":
            return 0, DIST_UPGRADE
        if argv[0] == "apt-mark":
            raise OSError("boom")
        if argv[0] == "dpkg-query":
            return 1, ""
        return 0, "enabled\n"

    monkeypatch.setattr(pk, "run", fake_run)
    d = pk.collect_sync()
    assert d["security_count"] == 2 and d["held"] == []
    assert set(d["errors"]) == {"held"} and "boom" in d["errors"]["held"]
    assert d["kernel"]["managed"] is False and d["needrestart"] == {"installed": False}
    assert d["daily_timer"] == "enabled"


def test_every_subprocess_has_timeout_and_c_locale():
    import inspect
    assert "timeout=TIMEOUT" in inspect.getsource(pk.run) and pk.ENV["LC_ALL"] == "C" and pk.TIMEOUT == 120


# ---- findings ---------------------------------------------------------------

def rules(d, taken_at=None):
    snaps = {"packages": snap(d, taken_at)}
    return {f.rule: f for f in findings.evaluate(snaps, Config())}


def test_security_finding():
    sec = [upd(f"p{i}", True) for i in range(7)]
    f = rules(data(updates=sec, security_count=7))["pkg.security_updates"]
    assert f.severity == "high" and f.title == "7 security updates waiting"
    assert "p0, p1, p2, p3, p4 and 2 more" in f.detail and "sudo apt upgrade" in f.detail
    assert f.link == "/packages#security"
    assert "pkg.updates" not in rules(data(updates=sec, security_count=7))


def test_security_finding_medium_when_lists_old_and_unattended():
    d = data(updates=[upd("a", True)], security_count=1, lists_age=time.time() - 5 * 86400,
             unattended_upgrades=True)
    r = rules(d)
    assert r["pkg.security_updates"].severity == "medium" and "unattended-upgrades" in r["pkg.security_updates"].detail
    assert r["pkg.security_updates"].title == "1 security update waiting"
    assert r["pkg.lists_stale"].title == "Package lists are 5 days old"


def test_other_updates_finding():
    r = rules(data(updates=[upd("a"), upd("b")]))
    assert r["pkg.updates"].severity == "low" and r["pkg.updates"].title == "2 updates waiting"
    assert set(r) == {"pkg.updates"}


def test_reboot_finding_both_reasons():
    r = rules(data(reboot={"required": True, "pkgs": ["libc6", "linux-image-6.12.57"]},
                   kernel={"managed": True, "running": "6.12.48", "newer_installed": "6.12.57"}))
    f = r["pkg.reboot"]
    assert f.severity == "medium" and f.title == "Reboot needed"
    assert "libc6" in f.detail and "6.12.57 is installed, 6.12.48 is running" in f.detail
    only_kernel = rules(data(kernel={"managed": True, "running": "6.12.48", "newer_installed": "6.12.57"}))
    assert "pkg.reboot" in only_kernel
    assert "pkg.reboot" not in rules(data(kernel={"managed": False, "running": "6.1"}))


def test_restart_finding():
    svcs = [f"s{i}.service" for i in range(6)]
    f = rules(data(needrestart={"installed": True, "services": svcs}))["pkg.restart"]
    assert f.severity == "low" and f.title == "6 services use old libraries" and "and 1 more" in f.detail
    assert "needrestart -r a" in f.detail
    assert rules(data(needrestart={"installed": True, "services": ["a.service"]}))["pkg.restart"].title == \
        "1 service uses old libraries"


def test_no_findings_when_unavailable_or_clean():
    assert findings.evaluate({"packages": snap({"available": False, "reason": "x"})}, Config()) == []
    assert rules(data()) == {}


# ---- events -----------------------------------------------------------------

def test_events():
    prev = data(updates=[upd("a", True)])
    cur = data(updates=[upd("a", True), upd("b", True), upd("c", True), upd("d")],
               reboot={"required": True, "pkgs": []})
    ev = runner.diff_events("packages", prev, cur, (1, 2))
    assert [e["title"] for e in ev] == ["2 new security updates", "Reboot needed"]
    assert ev[0]["severity"] == "medium" and ev[0]["link"] == "/packages#security"
    assert runner.diff_events("packages", cur, cur, (1, 2)) == []
    assert runner.diff_events("packages", prev, data(updates=[upd("d")]), (1, 2)) == []


# ---- page -------------------------------------------------------------------

FULL = dict(
    updates=[upd("libssl3t64", True, "3.5.1-1"), upd("tzdata"), upd("cowsay", current=None)], security_count=1,
    held=["nginx"], kept_back=["linux-image-amd64"], removals=1,
    reboot={"required": True, "pkgs": ["libc6"]},
    kernel={"managed": True, "running": "6.12.48", "newer_installed": "6.12.57"},
    needrestart={"installed": True, "services": ["cron.service"]})


def check_page(html, base=""):
    assert 'id="pkg-libssl3t64"' in html and 'id="pkg-tzdata"' in html and 'id="pkg-nginx"' in html
    assert "Security updates" in html and "Other updates" in html and "Held packages" in html
    assert "Reboot and restarts" in html and "cron.service" in html and "libc6" in html
    assert 'data-label="Installed"' in html and "uname -r" in html and "apt list --upgradable" in html
    assert "sudo needrestart -b -r l" in html and "ls -lt /var/lib/apt/lists/*InRelease | head -3" in html
    assert f'hx-get="{base}/partials/packages"' in html
    assert f'aria-current="page" href="{base}/packages"' in html
    assert check_panels(html) >= 5


def test_packages_page_single_host(cfg):
    conn = db.connect_writer(cfg.db_path)
    db.put_snapshot(conn, "testhost", "packages", db.now(), True, None, data(**FULL))
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    check_page(c.get("/packages").text)
    assert c.get("/partials/packages").text.lstrip().startswith('<div id="live"')
    assert "1 security" in c.get("/").text


def test_packages_page_empty_and_unmanaged(cfg):
    conn = db.connect_writer(cfg.db_path)
    db.put_snapshot(conn, "testhost", "packages", db.now(), True, None, data())
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    html = c.get("/packages").text
    assert "No security updates waiting." in html and "Kernel managed by the host" in html
    assert "needrestart isn't installed" in html and "sudo apt install needrestart" in html
    assert check_panels(html) >= 5


def test_packages_page_unavailable(cfg):
    conn = db.connect_writer(cfg.db_path)
    db.put_snapshot(conn, "testhost", "packages", db.now(), True, None,
                    {"available": False, "reason": "This host uses neither apt and dpkg nor dnf and rpm"})
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    html = c.get("/packages").text
    assert "uses neither apt" in html and check_panels(html) >= 0


# ---- hub --------------------------------------------------------------------

def test_hub_accepts_and_shows_packages(hub_cfg, token):  # noqa: F811
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    snaps = [{"source": "packages", "taken_at": time.time(), "ok": True, "error": None, "data": data(**FULL)}]
    assert post(c, body(snapshots=snaps), token).status_code == 200
    bad = [{"source": "packages", "taken_at": 1, "ok": True, "error": None, "data": {"updates": "no"}}]
    assert post(c, body(snapshots=bad), token).status_code == 422
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    r = c.get("/h/testhost/packages")
    assert r.status_code == 200
    check_page(r.text, "/h/testhost")
    assert c.get("/h/testhost/partials/packages").status_code == 200
    assert c.get("/packages").status_code == 404


def test_build_sources_includes_packages():
    names = [s.name for s in runner.build_sources(Config())]
    assert "packages" in names
    assert [s.interval for s in runner.build_sources(Config()) if s.name == "packages"] == [3600]
