"""OS support status: release data, os-release parsing, findings and where they show."""

import re
from datetime import date

import pytest
from fastapi.testclient import TestClient

from daemonsight import db, distro, findings, hub
from daemonsight.collector.sources.system import SystemSource
from daemonsight.db import Snapshot
from daemonsight.web.app import create_app

from .conftest import PASSWORD
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_provenance import check_panels

DEBIAN12 = {"os_id": "debian", "version_id": "12", "version_codename": "bookworm"}
DEBIAN11 = {"os_id": "debian", "version_id": "11", "version_codename": "bullseye"}
UBUNTU2204 = {"os_id": "ubuntu", "version_id": "22.04", "version_codename": "jammy"}


@pytest.fixture(autouse=True)
def bundled_only(monkeypatch):
    """Ignore the machine's own /usr/share/distro-info so results are fixed."""
    monkeypatch.setattr(distro, "_system_text", lambda d: None)


def ev(ident, y, m, d):
    return distro.evaluate(ident, date(y, m, d))


# --- release data ------------------------------------------------------------

def test_bundled_data_loads_with_importlib_resources():
    from importlib import resources
    base = resources.files("daemonsight.data") / "distro-info"
    for name in ("debian.csv", "ubuntu.csv", "COPYRIGHT", "README.md"):
        assert (base / name).is_file(), name
    assert "ISC" in (base / "COPYRIGHT").read_text()
    rows = distro.parse_csv(distro.bundled_text("debian"))
    bookworm = distro.find_row(rows, "12", None)
    assert bookworm["series"] == "bookworm" and bookworm["eol-lts"] == date(2028, 6, 30)
    assert distro.find_row(rows, None, "trixie")["version"] == "13"
    ubuntu = distro.parse_csv(distro.bundled_text("ubuntu"))
    assert distro.find_row(ubuntu, "22.04", None)["series"] == "jammy"


def test_wheel_config_includes_the_data():
    import tomllib
    from pathlib import Path
    cfg = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert "distro-info/*" in cfg["tool"]["setuptools"]["package-data"]["daemonsight.data"]


def test_system_copy_wins_when_it_has_the_release(monkeypatch):
    newer = "version,codename,series,created,release,eol,eol-lts,eol-elts\n" \
            "12,Bookworm,bookworm,2021-08-14,2023-06-10,2026-07-11,2027-01-01,2033-06-30\n"
    monkeypatch.setattr(distro, "_system_text", lambda d: newer)
    assert ev(DEBIAN12, 2026, 11, 18).label == "LTS until 2027-01-01"
    # A system copy without the release falls back to the bundled one.
    monkeypatch.setattr(distro, "_system_text", lambda d: "version,codename,series,created,release,eol\n"
                                                       "1.1,Buzz,buzz,1993-08-16,1996-06-17,1997-06-05\n")
    assert ev(DEBIAN12, 2026, 11, 18).label == "LTS until 2028-06-30"


# --- evaluation at fixed dates -------------------------------------------------

def test_debian_stages():
    s = ev(DEBIAN12, 2026, 1, 1)
    assert (s.status, s.label) == ("supported", "Supported")
    s = ev(DEBIAN12, 2026, 11, 18)
    assert (s.status, s.label) == ("extended", "LTS until 2028-06-30")
    assert s.current == "Debian 13 (trixie)" and s.name == "Debian 12"
    s = ev(DEBIAN11, 2026, 11, 18)
    assert s.status == "ended"
    assert s.label == "No free security updates (ELTS only, paid) since 2026-08-31"
    assert ev(DEBIAN11, 2031, 7, 1).label == "End of life"
    assert ev(DEBIAN11, 2024, 1, 1).status == "supported"
    assert ev(DEBIAN11, 2025, 1, 1).label == "LTS until 2026-08-31"


def test_ubuntu_stages():
    assert ev(UBUNTU2204, 2026, 1, 1).label == "Supported"
    s = ev(UBUNTU2204, 2027, 7, 1)
    assert (s.status, s.label) == ("extended", "ESM only (Ubuntu Pro) until 2032-04-21")
    assert s.current == "Ubuntu 26.04 (resolute)"
    assert ev(UBUNTU2204, 2033, 1, 1).label == "End of life"
    non_lts = {"os_id": "ubuntu", "version_id": "25.10", "version_codename": "questing"}
    assert ev(non_lts, 2026, 8, 1).label == "End of life"


def test_unknown_when_out_of_scope():
    assert ev({"os_id": "arch", "version_id": "rolling"}, 2026, 11, 18).status == "unknown"
    assert ev({}, 2026, 11, 18).status == "unknown"
    assert ev({"os_id": "debian", "version_codename": "sid"}, 2026, 11, 18).status == "unknown"
    assert ev({"os_id": "debian", "version_id": "99"}, 2026, 11, 18).status == "unknown"
    mint = {"os_id": "linuxmint", "os_like": ["ubuntu", "debian"], "version_id": "22", "version_codename": "wilma"}
    assert ev(mint, 2026, 11, 18).status == "unknown"


# --- os-release parsing ----------------------------------------------------------

DEBIAN_OSR = '''PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.1
ID=debian
HOME_URL="https://www.debian.org/"
'''

RASPBIAN_OSR = '''PRETTY_NAME="Raspbian GNU/Linux 12 (bookworm)"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=raspbian
ID_LIKE=debian
'''


def test_parse_os_release():
    f = distro.parse_os_release(DEBIAN_OSR)
    assert f["PRETTY_NAME"] == "Debian GNU/Linux 13 (trixie)"
    assert distro.os_ident(f) == {"os_id": "debian", "os_like": [], "version_id": "13",
                                  "version_codename": "trixie"}
    ident = distro.os_ident(distro.parse_os_release(RASPBIAN_OSR))
    assert ident["os_id"] == "raspbian" and ident["os_like"] == ["debian"]
    # Raspberry Pi OS is judged as Debian, by codename.
    s = ev(ident, 2026, 11, 18)
    assert s.distro == "debian" and s.status == "extended" and s.name == "Debian 12"
    assert distro.parse_os_release("# c\n\nbad line\nID='ubuntu'\n") == {"ID": "ubuntu"}


async def test_system_source_carries_os_fields():
    src = SystemSource()
    data = await src.collect()
    for key in ("os", "os_id", "os_like", "version_id", "version_codename"):
        assert key in data


# --- findings --------------------------------------------------------------------

def snaps_for(ident):
    return {"system": Snapshot("system", 0, True, None, {"os": "x", "kernel": "6", "disks": [], **ident})}


def run(ident, y, m, d, cfg=None):
    from daemonsight.config import Config
    out = findings.evaluate(snaps_for(ident), cfg or Config(), {"today": date(y, m, d)})
    return {f.rule: f for f in out if f.rule.startswith("os.")}


def test_lts_finding():
    f = run(DEBIAN12, 2026, 11, 18)["os.lts"]
    assert f.severity == "low" and f.title == "Debian 12 is on LTS until 2028-06-30"
    assert "Regular security support ended 2026-07-11" in f.detail
    assert "fewer packages" in f.detail and "https://wiki.debian.org/LTS" in f.detail
    assert "Debian 13 (trixie)" in f.detail and f.link == "/#os"
    assert run(DEBIAN12, 2028, 1, 15)["os.lts"].severity == "medium"  # inside 180 days of the end
    assert run(DEBIAN12, 2027, 12, 1)["os.lts"].severity == "low"


def test_eol_finding():
    f = run(DEBIAN11, 2026, 11, 18)["os.eol"]
    assert f.severity == "high" and f.title == "Debian 11 no longer gets security updates"
    assert "Debian 13 (trixie)" in f.detail and "os.lts" not in run(DEBIAN11, 2026, 11, 18)
    assert "os.eol" in run(DEBIAN11, 2032, 1, 1)
    assert run(UBUNTU2204, 2033, 1, 1)["os.eol"].title == "Ubuntu 22.04 no longer gets security updates"
    assert run(UBUNTU2204, 2027, 7, 1)["os.lts"].title.startswith("Ubuntu 22.04 is on ESM until")


def test_no_finding_when_supported_or_unknown():
    assert run(DEBIAN12, 2026, 1, 1) == {}
    assert run({"os_id": "fedora"}, 2026, 11, 18) == {}
    assert run({"os_id": "debian", "version_id": "13", "version_codename": "trixie"}, 2026, 11, 18) == {}


# --- pages ---------------------------------------------------------------------------

class FixedDate(date):
    @classmethod
    def today(cls):
        return cls(2026, 11, 18)


@pytest.fixture
def fixed_today(monkeypatch):
    monkeypatch.setattr(distro, "date", FixedDate)
    monkeypatch.setattr(findings, "date", FixedDate)


def system_data(ts, ident):
    return {"os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-99-amd64", "virt": None,
            "boot_time": ts - 86400 * 41, "os_like": [], **ident,
            "cpu": {"percent": 23.0, "count": 2, "load": [0.4, 0.3, 0.3]},
            "memory": {"total": 4 * 2**30, "available": 1 * 2**30, "percent": 75.0, "swap_total": 0, "swap_used": 0},
            "disks": [{"mount": "/", "device": "/dev/vda1", "fstype": "ext4", "total": 58e9, "used": 31e9,
                       "percent": 54.0}],
            "net": {"eth0": {"rx_bps": 1.8e6, "tx_bps": 6e5}}}


def test_overview_menu_line_and_finding_link(cfg, fixed_today):
    conn = db.connect_writer(cfg.db_path)
    ts = db.now()
    db.put_snapshot(conn, "testhost", "system", ts, True, None, system_data(ts, DEBIAN12))
    snaps = db.get_snapshots(conn, "testhost")
    db.reconcile_findings(conn, "testhost", ts, findings.evaluate(snaps, cfg))
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    html = c.get("/").text
    assert "Debian 12 is on LTS until 2028-06-30" in html
    # The finding's link names an id the page renders.
    links = re.findall(r'href="(/#[^"]+)"', html)
    assert "/#os" in links
    for link in links:
        assert f'id="{link[2:]}"' in html, link
    assert "LTS until 2028-06-30" in html.split('id="os"', 1)[1].split("datagrid-item", 1)[0]
    # Phone menu line: OS, support status, kernel and uptime, ahead of the account controls.
    menu = re.search(r'<div class="ds-menu-host[^>]*>(.*?)</div>', html, re.S).group(1)
    assert "Debian GNU/Linux 12 (bookworm)" in menu and "LTS until 2028-06-30" in menu
    assert "kernel 6.1.0-99-amd64" in menu and "up 41 d" in menu
    assert html.index("ds-menu-host") < html.index('action="/theme"')
    assert ".ds-menu-host" in c.get("/static/app.css").text
    check_panels(html)
    assert 'class="ds-menu-host' in c.get("/exposure").text


def test_menu_line_plain_when_supported(cfg, fixed_today):
    conn = db.connect_writer(cfg.db_path)
    ts = db.now()
    db.put_snapshot(conn, "testhost", "system", ts, True, None,
                    system_data(ts, {"os_id": "debian", "version_id": "13", "version_codename": "trixie"}))
    conn.close()
    c = TestClient(create_app(cfg), follow_redirects=False)
    c.post("/login", data={"password": PASSWORD, "next": "/"})
    menu = re.search(r'<div class="ds-menu-host[^>]*>(.*?)</div>', c.get("/").text, re.S).group(1)
    assert "badge" not in menu and "kernel 6.1.0-99-amd64" in menu


def test_hosts_page_reboot_badge_and_kernel(hub_cfg, fixed_today):  # noqa: F811
    conn = db.connect_writer(hub_cfg.db_path)
    hub.add_host(conn, "testhost")
    hub.add_host(conn, "quiet")
    ts = db.now()
    db.put_snapshot(conn, "testhost", "system", ts, True, None, system_data(ts, DEBIAN11))
    db.put_snapshot(conn, "quiet", "system", ts, True, None,
                    system_data(ts, {"os_id": "debian", "version_id": "13", "version_codename": "trixie"}))
    db.reconcile_findings(conn, "testhost", ts, [
        findings.Finding("pkg.reboot", "reboot", "medium", "Reboot needed", "x", "/packages#reboot")])
    conn.close()
    c = TestClient(create_app(hub_cfg), follow_redirects=False)
    assert c.post("/login", data={"password": PASSWORD, "next": "/"}).status_code == 303
    html = c.get("/").text
    rows = dict(re.findall(r'<tr data-row>\s*<td data-label="Host"><a href="/h/(\w+)/"(.*?)</tr>', html, re.S))
    assert 'href="/h/testhost/packages#reboot"' in rows["testhost"] and "Reboot needed" in rows["testhost"]
    assert "Reboot needed" not in rows["quiet"]
    assert "kernel 6.1.0-99-amd64 · up 41 d" in rows["testhost"]
    assert "No free security updates (ELTS only, paid) since 2026-08-31" in rows["testhost"]
    assert "badge" not in re.search(r'data-label="System">(.*?)</td>', rows["quiet"], re.S).group(1)  # supported: no badge
    assert 'data-label="State"' in rows["testhost"] and 'data-label="System"' in rows["testhost"]
    part = c.get("/partials/hosts").text
    assert part.lstrip().startswith('<div id="live"') and "Reboot needed" in part
    assert 'class="ds-menu-host' not in html  # no single host on the hub page
    assert 'class="ds-menu-host' in c.get("/h/testhost/").text
    # The reboot link resolves to a page that has the anchor.
    assert 'id="reboot"' in c.get("/h/testhost/packages").text
