"""Fedora: the dnf backend, OS support dates, install.sh, and the workstation role."""

import gzip
import json
import logging
import subprocess
import time
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from daemonsight import config, db, distro, findings, hub
from daemonsight.collector import upload
from daemonsight.collector.sources import SourceUnavailable, packages as pk
from daemonsight.config import Config
from daemonsight.web import provenance as prov
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import body, hub_cfg, post, token  # noqa: F401 (fixtures)
from .test_packages import check_page, data as apt_data, snap
from .test_provenance import check_panels

FX = Path(__file__).parent / "fixtures" / "dnf"
ROOT = Path(__file__).parents[1]


def fx(name: str) -> str:
    return (FX / name).read_text()


# ---- backend selection ------------------------------------------------------

def test_backend_follows_path(monkeypatch):
    calls = []
    monkeypatch.setattr(pk, "collect_apt", lambda: calls.append("apt") or {})
    monkeypatch.setattr(pk, "collect_dnf", lambda: calls.append("dnf") or {})
    have = {"dpkg", "apt-get", "dnf", "rpm"}
    monkeypatch.setattr(pk.shutil, "which", lambda n: f"/usr/bin/{n}" if n in have else None)
    pk.collect_sync()
    have -= {"dpkg", "apt-get"}
    pk.collect_sync()
    assert calls == ["apt", "dnf"]
    have.clear()
    with pytest.raises(SourceUnavailable):
        pk.collect_sync()


def test_dnf4_is_not_supported(monkeypatch):
    monkeypatch.setattr(pk, "run", lambda argv: (0, "4.18.0\n  Installed: dnf-0:4.18.0\n"))
    with pytest.raises(SourceUnavailable, match="not dnf5"):
        pk.collect_dnf()
    assert pk.is_dnf5(fx("dnf-version.txt"))


# ---- parsing ----------------------------------------------------------------

def test_parse_upgrades_and_security_flag():
    ups = pk.parse_upgrades(fx("check-upgrade.json"))
    sec = pk.parse_upgrades(fx("check-upgrade-security.json"))
    installed = pk.parse_rpm_evr(fx("rpm-evr.txt"))
    assert installed[("vim-minimal", "x86_64")] == ["2:9.2.1202-1.fc44"]
    assert ("nosuchpkg", "x86_64") not in installed  # "not installed" line skipped
    out = {u["name"]: u for u in pk.build_dnf_updates(ups, sec, installed)}
    assert out["dnf5"] == {"name": "dnf5", "current": "5.4.6.0-1.fc44", "candidate": "5.4.8.0-2.fc44",
                           "origin": "updates", "arch": "x86_64", "security": True}
    assert out["libmodulemd"]["security"] and out["libmodulemd"]["current"] == "2.15.3-1.fc44"
    assert not out["tzdata"]["security"] and out["tzdata"]["current"] == "2026e-1.fc44"
    assert out["vim-minimal"]["candidate"] == "2:9.2.1302-2.fc44"
    assert out["file-libs"]["current"] is None  # not in the rpm output: shown as new


def test_parse_upgrades_empty():
    assert pk.parse_upgrades("") == [] and pk.parse_upgrades('{"upgrades":[]}') == []


def test_versionlock_and_kernel_and_rpmvercmp():
    assert pk.parse_versionlock(fx("versionlock-list.txt")) == ["tzdata"]
    assert pk.parse_versionlock("") == []
    kernels = pk.parse_rpm_kernels("7.3.4-200.fc44.x86_64\n7.3.10-200.fc44.x86_64\npackage kernel-core is not installed\n")
    assert kernels == ["7.3.4-200.fc44.x86_64", "7.3.10-200.fc44.x86_64"]
    assert pk.kernel_state_rpm("7.3.4-200.fc44.x86_64", kernels) == \
        {"managed": True, "running": "7.3.4-200.fc44.x86_64", "newer_installed": "7.3.10-200.fc44.x86_64"}
    assert pk.kernel_state_rpm("7.3.10-200.fc44.x86_64", kernels)["newer_installed"] is None
    assert pk.kernel_state_rpm("6.18.38-Unraid", kernels) == {"managed": False, "running": "6.18.38-Unraid"}
    assert pk.parse_rpm_kernels(fx("kernel-core-rpm-qp.txt").replace("kernel-core ", "")) == ["7.3.4-200.fc44.x86_64"]
    assert pk.rpm_evr_gt("2:1.0-1", "1:9.9-1") and pk.rpm_evr_gt("1.10-1", "1.9-1")
    assert pk.rpm_evr_gt("1.0-1", "1.0~rc1-1") and not pk.rpm_evr_gt("1.0-1.fc44", "1.0-1.fc44")
    assert pk.rpm_evr_gt("2026f-1.fc44", "2026e-1.fc44")


def test_needs_restarting_parsing():
    assert pk.parse_needs_restarting_json(fx("needs-restarting-reboot.json")) == {"required": True, "pkgs": ["glibc"]}
    assert pk.parse_needs_restarting_json("[]") == {"required": False, "pkgs": []}
    assert pk.parse_needs_restarting_json(fx("nocache.txt")) is None
    assert pk.parse_needs_restarting_services("  * sshd.service\n  * cups.service\nnoise\n") == \
        ["cups.service", "sshd.service"]


# ---- collecting -------------------------------------------------------------

def fake_dnf(monkeypatch, *, cache=True, reboot_json=None, held=None):
    seen = []

    def fake_run(argv):
        seen.append(argv)
        key = argv[:2]
        if argv[0] == "dnf" and argv[1] == "--version":
            return 0, fx("dnf-version.txt")
        if key == ["dnf", "check-upgrade"]:
            if not cache:
                return 1, fx("nocache.txt")
            return 100, fx("check-upgrade-security.json" if "--security" in argv else "check-upgrade.json")
        if argv[0] == "rpm" and argv[1] == "-q" and argv[2] == "kernel-core":
            return 0, "7.3.4-200.fc44.x86_64\n7.3.10-200.fc44.x86_64\n"
        if argv[0] == "rpm":
            return 1, fx("rpm-evr.txt")
        if key == ["dnf", "versionlock"]:
            return 0, fx("versionlock-list.txt") if held is None else held
        if key == ["dnf", "needs-restarting"] and "-s" in argv:
            return (1, "  * sshd.service\n") if cache else (1, fx("nocache.txt"))
        if key == ["dnf", "needs-restarting"]:
            return (1, reboot_json) if reboot_json else (1, fx("nocache.txt"))
        return 0, "enabled\n"

    monkeypatch.setattr(pk, "run", fake_run)
    monkeypatch.setattr(pk.platform, "release", lambda: "7.3.4-200.fc44.x86_64")
    monkeypatch.setattr(pk, "newest_cache_mtime", lambda: 1000.0)
    return seen


def test_collect_dnf(monkeypatch):
    seen = fake_dnf(monkeypatch, reboot_json=fx("needs-restarting-reboot.json"))
    d = pk.collect_dnf()
    assert d["backend"] == "dnf" and d["errors"] == {}
    assert d["security_count"] == 2 and len(d["updates"]) == 5
    assert d["held"] == ["tzdata"] and d["lists_age"] == 1000.0 and d["daily_timer"] == "enabled"
    assert d["reboot"] == {"required": True, "pkgs": ["glibc"]}
    assert d["kernel"] == {"managed": True, "running": "7.3.4-200.fc44.x86_64",
                           "newer_installed": "7.3.10-200.fc44.x86_64"}
    assert d["needrestart"] == {"installed": True, "tool": "dnf", "services": ["sshd.service"]}
    # Nothing that changes the system or the cache, and never the network.
    for argv in seen:
        if argv[0] == "dnf" and argv[1] in ("check-upgrade", "needs-restarting"):
            assert "-C" in argv, argv
        assert argv[1] not in ("upgrade", "makecache", "install", "reinstall", "clean")


def test_collect_dnf_empty_cache_is_reported(monkeypatch):
    fake_dnf(monkeypatch, cache=False)
    d = pk.collect_dnf()
    assert "no dnf metadata cache" in d["errors"]["updates"] and d["updates"] == []
    assert d["needrestart"]["installed"] is False  # -s hit the same cache message
    assert set(d["errors"]) == {"updates"}


def test_reboot_falls_back_to_the_flag_file(monkeypatch, tmp_path):
    fake_dnf(monkeypatch)  # needs-restarting -C answers "no cache"
    flag = tmp_path / "reboot-required"
    monkeypatch.setattr(pk, "DNF_REBOOT_FILE", str(flag))
    assert pk.collect_dnf()["reboot"] == {"required": False, "pkgs": [], "checked": False}
    flag.write_text("")
    assert pk.collect_dnf()["reboot"]["required"] is True


def test_no_versionlock_plugin_means_nothing_held(monkeypatch):
    fake_dnf(monkeypatch)
    orig = pk.run
    monkeypatch.setattr(pk, "run", lambda argv: (2, "Unknown argument") if argv[:2] == ["dnf", "versionlock"]
                        else orig(argv))
    d = pk.collect_dnf()
    assert d["held"] == [] and "held" not in d["errors"]


def test_newest_cache_mtime(monkeypatch, tmp_path):
    repo = tmp_path / "fedora-abc" / "repodata"
    repo.mkdir(parents=True)
    (repo / "repomd.xml").write_text("x")
    monkeypatch.setattr(pk, "DNF_CACHE_GLOB", str(tmp_path / "*" / "repodata" / "repomd.xml"))
    assert abs(pk.newest_cache_mtime() - time.time()) < 60
    monkeypatch.setattr(pk, "DNF_CACHE_GLOB", str(tmp_path / "none" / "*"))
    assert pk.newest_cache_mtime() is None


# ---- findings and page ------------------------------------------------------

def dnf_data(**kw):
    base = apt_data(backend="dnf", daily_timer="enabled")
    base.update(kw)
    return base


def rules(d):
    return {f.rule: f for f in findings.evaluate({"packages": snap(d)}, Config())}


def test_findings_use_dnf_commands():
    sec = [{"name": "dnf5", "current": "1", "candidate": "2", "origin": "updates", "arch": "x86_64", "security": True}]
    r = rules(dnf_data(updates=sec, security_count=1))
    assert "sudo dnf upgrade --refresh" in r["pkg.security_updates"].detail
    assert "apt" not in r["pkg.security_updates"].detail
    other = [{**sec[0], "security": False}]
    assert "sudo dnf upgrade --refresh" in rules(dnf_data(updates=other))["pkg.updates"].detail
    assert "systemctl restart" in rules(dnf_data(needrestart={"installed": True, "services": ["a.service"]}))["pkg.restart"].detail
    stale = rules(dnf_data(lists_age=time.time() - 5 * 86400))["pkg.lists_stale"]
    assert "dnf5-makecache" in stale.detail
    assert "dnf needs-restarting" in rules(dnf_data(reboot={"required": True, "pkgs": []}))["pkg.reboot"].detail
    # apt hosts keep their text
    apt = rules(apt_data(updates=other))
    assert "sudo apt upgrade" in apt["pkg.updates"].detail


def test_provenance_per_backend():
    assert "dnf check-upgrade -C" in str(prov.packages("other", "dnf")) and "apt" not in str(prov.packages("other", "dnf"))
    assert "apt list --upgradable" in str(prov.packages("other"))
    sec = prov.section("packages", Config(), {"backend": "dnf"})
    assert "libdnf5" in sec["read"] and "apt" not in sec["read"]
    assert "apt-get" in prov.section("packages", Config())["read"]
    for part in prov.PACKAGES_PARTS_DNF:
        assert prov.packages(part, "dnf")["entries"]


def test_packages_page_on_dnf(cfg):
    conn = db.connect_writer(cfg.db_path)
    ups = [{"name": "dnf5", "current": "5.4.6.0-1.fc44", "candidate": "5.4.8.0-2.fc44", "origin": "updates",
            "arch": "x86_64", "security": True},
           {"name": "tzdata", "current": "2026e-1.fc44", "candidate": "2026f-1.fc44", "origin": "updates",
            "arch": "noarch", "security": False}]
    db.put_snapshot(conn, "testhost", "packages", db.now(), True, None,
                    dnf_data(updates=ups, security_count=1, held=["kernel-core"],
                             needrestart={"installed": False, "tool": "dnf"}))
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    html = c.get("/packages").text
    assert "dnf and rpm" in html and "dnf check-upgrade -C --security" in html
    assert "rpm -q kernel-core" in html and "dnf5-makecache.timer is enabled" in html
    assert "never runs dnf makecache" in html and "dnf5-plugins" in html
    assert "apt list" not in html and "apt-get" not in html and "apt-daily" not in html
    assert 'id="pkg-dnf5"' in html and 'id="pkg-kernel-core"' in html
    assert check_panels(html) >= 5


# ---- Fedora support dates ---------------------------------------------------

F43 = {"os_id": "fedora", "version_id": "43"}
F44 = {"os_id": "fedora", "version_id": "44"}


@pytest.fixture
def support_rules():
    def run(ident, y, m, d):
        today = date(y, m, d)
        snaps = {"system": snap({"os": "Fedora Linux", "disks": [], "memory": {"percent": 10.0}, **ident})}
        return {f.rule: f for f in findings.evaluate(snaps, Config(), {"today": today})}
    return run


def test_bundled_fedora_data():
    from importlib import resources
    base = resources.files("daemonsight.data") / "fedora"
    assert (base / "fedora.csv").is_file() and "endoflife.date" in (base / "README.md").read_text()
    rows = distro.parse_csv(distro.bundled_text("fedora"))
    f44 = distro.find_row(rows, "44", None)
    assert f44["eol"] == date(2027, 6, 2) and f44["state"] == "current"
    import tomllib
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "fedora/*" in cfg["tool"]["setuptools"]["package-data"]["daemonsight.data"]


def test_fedora_supported_then_eol():
    s = distro.evaluate(F43, date(2026, 11, 18))
    assert (s.status, s.label, s.name, s.eol) == ("supported", "Supported", "Fedora 43", date(2026, 12, 1))
    assert s.current == "Fedora 45"  # newest release that is out
    assert distro.evaluate(F43, date(2026, 11, 30)).status == "supported"
    e = distro.evaluate(F43, date(2026, 12, 1))
    assert e.status == "eol" and e.label == "End of life" and not e.plain
    assert distro.evaluate({"os_id": "fedora", "version_id": "40"}, date(2026, 11, 18)).status == "eol"
    assert distro.evaluate({"os_id": "fedora", "version_id": "35"}, date(2026, 11, 18)).status == "eol"  # no date known
    assert distro.evaluate(F44, date(2027, 6, 1)).status == "supported"


def test_fedora_unknown_cases():
    assert distro.evaluate({"os_id": "fedora", "version_id": "46"}, date(2026, 11, 18)).status == "unknown"  # Rawhide
    assert distro.evaluate({"os_id": "fedora", "version_id": "99"}, date(2026, 11, 18)).status == "unknown"
    assert distro.evaluate({"os_id": "fedora"}, date(2026, 11, 18)).status == "unknown"


def test_fedora_release_without_announced_eol(monkeypatch):
    text = "version,eol,state\n44,,current\n"
    monkeypatch.setattr(distro, "bundled_text", lambda d: text)
    s = distro.evaluate(F44, date(2030, 1, 1))
    assert s.status == "supported" and s.eol is None


def test_os_eol_soon_finding(support_rules):
    assert "os.eol_soon" not in support_rules(F43, 2026, 10, 1)  # 61 days before EOL
    r = support_rules(F43, 2026, 10, 3)  # 60 days
    f = r["os.eol_soon"]
    assert f.severity == "low" and f.title == "Fedora 43 support ends on 2026-12-01" and f.link == "/#os"
    assert "--releasever=45" in f.detail and "sudo dnf system-upgrade download" in f.detail
    assert "os.eol" not in r and "os.lts" not in r
    assert "os.eol_soon" not in support_rules(F44, 2026, 11, 18)


def test_os_eol_finding_for_fedora(support_rules):
    r = support_rules(F43, 2026, 12, 3)
    assert r["os.eol"].severity == "high" and r["os.eol"].title == "Fedora 43 no longer gets security updates"
    assert "Fedora 45" in r["os.eol"].detail and "os.eol_soon" not in r


def test_os_release_fixture_parses_to_fedora():
    ident = distro.os_ident(distro.parse_os_release(fx("os-release-fedora44.txt")))
    assert ident["os_id"] == "fedora" and ident["version_id"] == "44" and ident["version_codename"] is None
    assert distro.evaluate(ident, date(2026, 11, 18)).status == "supported"


# ---- install.sh -------------------------------------------------------------

def test_install_script_is_valid_bash():
    assert subprocess.run(["bash", "-n", str(ROOT / "install.sh")]).returncode == 0
    text = (ROOT / "install.sh").read_text()
    assert "dnf install python3" in text and "command -v restorecon" in text
    assert "/usr/sbin/nologin" in text


# ---- workstation role -------------------------------------------------------

def test_role_validation_and_default(caplog):
    assert Config().role == "server"
    assert config.valid_role("workstation") == "workstation" and config.valid_role(" Server ") == "server"
    with caplog.at_level(logging.WARNING, logger="daemonsight"):
        assert config.valid_role("laptop", warn=True) == "server"
    assert "unknown role" in caplog.text


def test_role_loads_from_the_config_file(tmp_path, caplog):
    p = tmp_path / "config.toml"
    p.write_text('role = "workstation"\n')
    assert config.load(p).role == "workstation"
    p.write_text('role = "desktop"\n')
    with caplog.at_level(logging.WARNING, logger="daemonsight"):
        assert config.load(p).role == "server"
    assert "unknown role" in caplog.text
    p.write_text("")
    assert config.load(p).role == "server"


def test_upload_settings_carry_the_role(cfg):
    conn = db.connect_writer(cfg.db_path)
    assert upload.build(conn, cfg, (32768, 60999), 30)[0]["settings"]["role"] == "server"
    cfg.role = "workstation"
    payload = upload.build(conn, cfg, (32768, 60999), 30)[0]
    assert payload["settings"]["role"] == "workstation"
    assert hub.Upload.model_validate({**payload, "seq": 1, "sent_at": time.time()}).settings.role == "workstation"
    conn.close()


def test_hub_role_is_optional_and_checked():
    assert hub.SettingsIn().role == "server" and hub.SettingsIn.model_validate({"links": {}}).role == "server"
    with pytest.raises(Exception):
        hub.SettingsIn.model_validate({"role": "laptop"})


def store_role(hub_cfg, token, role, sent):
    conn = db.connect_writer(hub_cfg.db_path)
    row = hub.host_for_token(conn, token)
    settings = {} if role is None else {"settings": {"role": role}}
    up = hub.Upload.model_validate(json.loads(gzip.decompress(body(seq=int(sent * 1000), **settings))))
    up.sent_at = sent
    hub.store(conn, row, up, sent, "203.0.113.9")
    return conn


@pytest.mark.parametrize("role", [None, "server"])
def test_silent_server_is_high(hub_cfg, token, role):
    now = time.time()
    conn = store_role(hub_cfg, token, role, now)
    hub.check_silent(conn, now + 3 * 60 + 1)
    f = [x for x in db.open_findings(conn, "testhost") if x["rule"] == "host.silent"][0]
    assert f["severity"] == "high" and f["title"] == "Stopped reporting"


def test_silent_workstation_is_low_and_offline(hub_cfg, token):
    now = time.time()
    conn = store_role(hub_cfg, token, "workstation", now)
    hub.check_silent(conn, now + 3 * 60 + 1)
    f = [x for x in db.open_findings(conn, "testhost") if x["rule"] == "host.silent"][0]
    assert f["severity"] == "low" and f["title"].startswith("Offline since 20") and f["title"].endswith("UTC")
    assert "workstation" in f["detail"] and "uploads again" in f["detail"]
    ev = db.recent_events(conn, "testhost")[0]
    assert ev["kind"] == "host_silent" and ev["severity"] == "low"
    # Back: resolved, as for a server.
    later = now + 1000
    store_role(hub_cfg, token, "workstation", later)
    assert not [x for x in db.open_findings(conn, "testhost") if x["rule"] == "host.silent"]
    assert db.recent_events(conn, "testhost")[0]["title"] == "Reporting again"


def test_workstation_that_never_reported_is_still_flagged(hub_cfg, token):
    conn = db.connect_writer(hub_cfg.db_path)
    hub.check_silent(conn, time.time() + 700)
    assert [f["title"] for f in db.open_findings(conn, "testhost")] == ["Never reported"]


def test_hosts_page_shows_role_and_offline(hub_cfg, token):
    now = time.time()
    conn = store_role(hub_cfg, token, "workstation", now - 3600)
    hub.check_silent(conn, now)
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    html = c.get("/").text
    assert "Workstation" in html and ">Offline<" in html and "Not reporting" not in html
    assert 'badge bg-secondary-lt">Offline' in html
    # The same host as a server: red "Not reporting", no role badge.
    store_role(hub_cfg, token, "server", now - 3000)
    hub.check_silent(conn, now)
    html = c.get("/").text
    assert "Not reporting" in html and "Workstation" not in html and ">Offline<" not in html


def test_single_host_overview_shows_role_only_for_workstations(cfg):
    from daemonsight.web import views
    conn = db.connect_writer(cfg.db_path)
    assert all(g["id"] != "role" for g in views.overview(conn, cfg)["glance"])
    cfg.role = "workstation"
    role = [g for g in views.overview(conn, cfg)["glance"] if g["id"] == "role"]
    assert role and role[0]["value"] == "Workstation"
    conn.close()
