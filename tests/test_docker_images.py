"""Container images: the base OS and its end of life (docker.eol_base), Debian, Ubuntu and Alpine CVE matching (docker.image_cves) and the
Container images page. Everything is synthetic: nginx, debian and alpine are public names, the rest is made up."""

import asyncio
import copy
import re
import time
from datetime import date

import httpx
import pytest

from daemonsight import db, distro
from daemonsight.cve import alpine, feeds, match, run, store as cvestore, ubuntu
from daemonsight.remote import docker_images as di
from daemonsight.remote import docker_storage as ds

from .fake_docker import IDS, standard_summary
from .test_alpine import secdb_gz
from .test_ubuntu import oval_bz2
from .test_cve import epss_gz, kev_gz, serve, tracker_gz
from .test_hub import hub_cfg  # noqa: F401 (fixture)
from .test_docker_storage import (READER, TOKEN, add_system, conn_of, form, open_rules, snap, web, world)  # noqa: F401 (fixtures)
from .test_provenance import check_panels

TODAY = date(2026, 11, 24)
NOW = 1_800_000_100.0


@pytest.fixture(autouse=True)
def bundled_only(monkeypatch):
    """Fixed release data and a fixed day, so a support status does not change with the machine or the calendar."""
    monkeypatch.setattr(distro, "_system_text", lambda d: None)

    class Day(date):
        @classmethod
        def today(cls):
            return TODAY
    monkeypatch.setattr(di, "date", Day)
    monkeypatch.setattr(distro, "date", Day)


@pytest.fixture(autouse=True)
def cve_on(request):
    """The hub test config has CVE matching off; these tests need it on (only the ones that use the hub)."""
    if "hub_cfg" in request.fixturenames:
        request.getfixturevalue("hub_cfg").cve.enabled = True


def os_(id_, version, codename="", pretty="", like=()):
    return {"id": id_, "like": list(like), "version_id": version, "codename": codename, "pretty": pretty}


DEB12 = os_("debian", "12", "bookworm", "Debian GNU/Linux 12 (bookworm)")
UBU24 = os_("ubuntu", "24.04", "noble", "Ubuntu 24.04.1 LTS")
UBUNTU_PACKAGES = [("libxml2", "", "2.9.14+dfsg-1.3ubuntu3", ""), ("libxml-parser-perl", "", "2.46-1", ""),
                   ("libxmltok1", "libxmltok", "1.2-4.1ubuntu2.24.0.4.1+esm2", ""), ("gcc-mingw-w64-base", "gcc-mingw-w64", "26ubuntu1", ""),
                   ("libssl3t64", "openssl", "3.0.13-0ubuntu3.4+b1", "3.0.13-0ubuntu3.4")]


def entry(iid, os_info, packages=None, manager="dpkg", error=None, container="web", read_at=1_800_000_000):
    pk = [list(p) + [""] * (4 - len(p)) for p in (packages or [])]
    return {"image_id": iid, "container": container, "read_at": read_at, "os": os_info, "manager": manager if packages is not None else None,
            "count": len(pk), "packages": pk, "error": error}


# nginx-like image: a package with a fixable KEV CVE, two fixable c-ares ones, one with no fix yet, and minor ones
BOOKWORM_PACKAGES = [("libbrotli1", "brotli", "1.0.9-2", ""), ("libc-ares2", "c-ares", "1.10.0-1", ""), ("edk2-ovmf", "edk2", "2020.1", ""),
                     ("libxml2", "", "2.9.14", ""), ("nodejs", "", "18.1", ""), ("libssl3", "openssl", "3.0.11-1+b1", "3.0.11-1")]


def summary_with(entries, containers=None):
    raw = standard_summary()
    raw["image_packages"] = entries
    if containers is not None:
        raw["containers"] = containers
    return raw


def stored(entries, containers=None):
    return ds.parse_summary(summary_with(entries, containers), None, None, NOW)


# --- what the hub stores ----------------------------------------------------------------------------------------------------

def test_the_stored_package_lists_are_checked_again_and_cut():
    good = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES)
    junk = [good, "x", {"image_id": "nope"}, {**entry(IDS["postgres"], DEB12, [("a", "", "1", "")]), "manager": "rpm"},
            {**entry(IDS["widget-new"], {"id": "A" * 100, "like": [1, "x"], "version_id": "1", "codename": "", "pretty": "p\x00q"}, [("a", "", "1", "")]),
             "packages": [["ok", "", "1", ""], ["bad"], [1, 2, 3], ["", "", "1", ""], ["x" * 500, "", "1", ""]]}]
    out = stored(junk)["image_packages"]
    assert [e["image_id"] for e in out] == [IDS["nginx"], IDS["postgres"], IDS["widget-new"]]
    assert out[0]["packages"][0] == ["libbrotli1", "brotli", "1.0.9-2", ""] and out[0]["os"]["codename"] == "bookworm"
    assert out[1]["manager"] is None                                 # an unknown package manager is dropped
    assert [p[0] for p in out[2]["packages"]] == ["ok", "x" * 100] and out[2]["os"]["pretty"] == "pq" and out[2]["os"]["like"] == ["x"]
    assert len(out[2]["os"]["id"]) == 40


def test_a_reader_without_package_lists_is_not_the_same_as_an_empty_list():
    raw = standard_summary()
    assert "image_packages" not in raw and ds.parse_summary(raw, None, None, NOW)["image_packages"] is None
    assert di.analyze(ds.parse_summary(raw, None, None, NOW)) is None and di.evaluate(ds.parse_summary(raw, None, None, NOW)) == []
    assert ds.parse_summary({**raw, "image_packages": []}, None, None, NOW)["image_packages"] == []


# --- the base OS and its end of life ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("os_info, status, eol", [
    (os_("debian", "10", "buster"), "ended", "2022-09-10"),
    (os_("debian", "11", "bullseye"), "ended", "2024-08-14"),
    (os_("debian", "12", "bookworm"), "extended", "2026-07-11"),
    (os_("debian", "13", "trixie"), "supported", "2028-08-09"),
    (os_("debian", "12"), "extended", "2026-07-11"),                  # no codename: the version finds the release
    (os_("ubuntu", "16.04", "xenial"), "eol", "2021-04-30"),
    (os_("ubuntu", "20.04", "focal"), "extended", "2025-05-29"),
    (os_("ubuntu", "24.04", "noble"), "supported", "2029-05-31"),
    (os_("alpine", "3.17.2"), "eol", "2024-11-22"),                   # the cycle is the first two parts
    (os_("alpine", "3.21.0"), "eol", "2026-11-01"),
    (os_("alpine", "3.22.1"), "supported", "2027-05-01"),
    (os_("alpine", "3.99.0"), "unknown", None),
    (os_("centos", "8", pretty="CentOS Linux 8"), "eol", "2021-12-31"),
    (os_("centos", "7", pretty="CentOS Linux 7"), "eol", "2024-06-30"),
    (os_("centos", "9", pretty="CentOS Stream 9"), "unknown", None),    # Stream is another product
    (os_("fedora", "40"), "eol", "2025-05-13"),
    (os_("void", ""), "unknown", None),
    (os_("debian", "", "sid"), "unknown", None),
])
def test_the_base_os_maps_to_a_support_status(os_info, status, eol):
    sup = di.support_of(os_info, TODAY)
    assert sup["status"] == status and sup["eol"] == eol
    assert (sup["label"] == "Unknown") == (status == "unknown")
    if status == "supported":
        assert sup["label"] == f"Supported until {eol}"             # a supported base shows its end date
    if status == "eol":
        assert sup["label"].startswith("End of life since ")


def test_the_alpine_and_centos_dates_are_bundled_and_come_from_endoflife_date():
    from importlib import resources
    base = resources.files("daemonsight.data") / "endoflife"
    assert "endoflife.date/api/v1/products/alpine-linux" in (base / "README.md").read_text()
    for name, first in (("alpine.csv", "2.1,"), ("centos.csv", "5,")):
        text = (base / name).read_text()
        assert text.startswith("version,released,eol\n") and first in text
    import tomllib
    from pathlib import Path
    cfg = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert "endoflife/*" in cfg["tool"]["setuptools"]["package-data"]["daemonsight.data"]


IDS3 = {n: IDS[n] for n in ("nginx", "postgres", "widget-new", "debian")}


def eol_world(*specs):
    """Entries for the running containers of the standard summary: (image name, os dict) pairs."""
    return [entry(IDS[n], o, [("a", "", "1", "")], manager="apk" if o["id"] == "alpine" else "dpkg") for n, o in specs]


def test_docker_eol_base_is_one_aggregate_finding_that_fires_and_clears():
    old = [("nginx", os_("debian", "10", "buster")), ("postgres", os_("alpine", "3.17.2")), ("widget-new", os_("alpine", "3.22.1"))]
    f = [x for x in di.evaluate(stored(eol_world(*old)), None, None, TODAY) if x.rule == "docker.eol_base"]
    assert len(f) == 1
    f = f[0]
    assert f.severity == "medium" and f.key == "all" and f.title == "2 container images run on an end-of-life OS"
    assert "nginx:1.27 (Debian 10)" in f.detail and "postgres:17 (Alpine 3.17)" in f.detail and "widget" not in f.detail
    assert "Check for Updates" in f.howto and "has not rebuilt it" in f.howto and f.link == "/images#image-list"
    assert not re.search(r"\d{4}-\d\d-\d\d", f.basis)                         # no dates: accepting it stays put
    one = [x for x in di.evaluate(stored(eol_world(old[0])), None, None, TODAY) if x.rule == "docker.eol_base"][0]
    assert one.title == "1 container image runs on an end-of-life OS" and one.basis != f.basis      # a new image brings it back
    # Updated to supported bases: nothing is raised. Debian LTS (still updated, fewer packages) is not an end of life either.
    ok = [("nginx", os_("debian", "12", "bookworm")), ("postgres", os_("alpine", "3.22.1")), ("widget-new", os_("ubuntu", "24.04", "noble"))]
    assert [x for x in di.evaluate(stored(eol_world(*ok)), None, None, TODAY) if x.rule == "docker.eol_base"] == []
    # An OS the data does not list is unknown, never counted.
    assert di.evaluate(stored(eol_world(("nginx", os_("void", "")))), None, None, TODAY) == []


def test_the_eol_basis_does_not_move_with_the_date_or_the_version_inside_a_cycle():
    a = [x for x in di.evaluate(stored(eol_world(("nginx", os_("alpine", "3.17.2")))), None, None, TODAY)][0]
    b = [x for x in di.evaluate(stored(eol_world(("nginx", os_("alpine", "3.17.9")))), None, None, date(2027, 6, 1))][0]
    assert a.basis == b.basis


# --- Debian CVE matching -------------------------------------------------------------------------------------------------------

@pytest.fixture
def cvedb(tmp_path):
    conn = cvestore.connect(tmp_path / "cve.db")
    feeds.load_debian(conn, tracker_gz(tmp_path), {"bookworm"})
    for feed in feeds.alpine_feeds("v3.23"):                       # the only Alpine release this fixture knows
        feeds.load_alpine(conn, secdb_gz(tmp_path, "v3.23", feed.repo), feed)
    feeds.load_ubuntu(conn, oval_bz2(tmp_path, "noble"), feeds.ubuntu_feed("noble"), {"linux"})      # the only Ubuntu release this fixture knows
    feeds.load_epss(conn, epss_gz(tmp_path))
    feeds.load_kev(conn, kev_gz(tmp_path))
    yield conn
    conn.close()


def matched(cvedb, entries, host="tower"):
    """What the chore does for images (matching under pseudo-host ids), then what load_cves gives the rules."""
    out, rels, ubu = {}, {}, {}
    for e in entries:
        inv = di.pseudo_inventory(e)
        if inv:
            ph = di.pseudo_host(host, e["image_id"])
            ubuntu_image = inv["os_id"] == "ubuntu" if inv["backend"] == "apt" else False
            (alpine.match_host if inv["backend"] == "apk" else ubuntu.match_host if ubuntu_image else match.match_host)(cvedb, ph, inv, "g")
            out[e["image_id"]] = {"matched": True, "cves": match.host_cves(cvedb, ph, ("fix", "esm", "nofix")),
                                  "note": cvedb.execute("SELECT note FROM matched WHERE host = ?", (ph,)).fetchone()["note"]}
            if inv["backend"] == "apk":
                has = cvedb.execute("SELECT 1 FROM apk WHERE release = ?", (inv["release"],)).fetchone()
                rels[inv["release"]] = {"state": "ok" if has else "absent", "ok_at": 1.0, "error": None}
            if ubuntu_image:
                has = cvedb.execute("SELECT 1 FROM ubu WHERE release = ?", (inv["codename"],)).fetchone()
                ubu[inv["codename"]] = {"state": "ok" if has else "absent", "ok_at": 1.0, "error": None}
    return {"enabled": True, "available": True, "epss_high": 0.10, "feed_at": 1.0, "alpine": rels, "ubuntu": ubu, "images": out}


def test_the_pseudo_inventory_groups_by_source_and_source_version_for_debian_and_by_origin_for_alpine():
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES + [("libbrotli-dev", "brotli", "1.0.9-2", "")])
    inv = di.pseudo_inventory(e)
    srcs = {s: (v, b) for s, v, b in inv["sources"]}
    assert srcs["brotli"] == ("1.0.9-2", ["libbrotli-dev", "libbrotli1"]) and srcs["openssl"] == ("3.0.11-1", ["libssl3"])   # the source's version, not the binary's +b1
    assert inv["os_id"] == "debian" and inv["codename"] == "bookworm" and inv["backend"] == "apt" and match.release_of(inv) == "bookworm"
    uin = di.pseudo_inventory(entry(IDS["nginx"], UBU24, [("libxml2", "", "2.9.14+dfsg-1.3ubuntu3", ""), ("libssl3t64", "openssl", "3.0.13-0ubuntu3.4+b1", "3.0.13-0ubuntu3.4")]))
    assert uin["os_id"] == "ubuntu" and uin["codename"] == "noble" and uin["backend"] == "apt" and uin["esm"] == [] and ubuntu.release_of(uin) == "noble"
    assert {s: v for s, v, _b in uin["sources"]} == {"libxml2": "2.9.14+dfsg-1.3ubuntu3", "openssl": "3.0.13-0ubuntu3.4"} and match.release_of(uin) is None
    assert di.ubuntu_codename(os_("ubuntu", "24.04", "")) == "noble" and di.ubuntu_codename(os_("ubuntu", "", "")) is None and di.ubuntu_codename(DEB12) is None
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("ubuntu", "", ""), [("a", "", "1", "")])) is None                  # no release name to look up
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("linuxmint", "21", "vanessa", like=["ubuntu", "debian"]), [("a", "", "1", "")])) is None
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("alpine", "3.24.0_alpha20260101"), [("a", "", "1", "")], manager="apk")) is None      # edge: no release name
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("alpine", "3.19"), [("a", "", "1", "")], manager="apk"))["backend"] == "apk"
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("kali", "2024", "kali-rolling", like=["debian"]), [("a", "", "1", "")])) is None
    assert di.pseudo_inventory(entry(IDS["nginx"], DEB12, None, error="not read: stopped")) is None
    # The codename comes from VERSION_ID when os-release lacks it; Raspberry Pi OS is Debian under its own name.
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("debian", "12", ""), [("a", "", "1", "")]))["codename"] == "bookworm"
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("raspbian", "12", "bookworm", like=["debian"]), [("a", "", "1", "")]))["codename"] == "bookworm"
    assert di.pseudo_host("tower", IDS["nginx"]).startswith("docker:tower:") and ":" not in "tower" and len(di.pseudo_host("tower", IDS["nginx"])) == len("docker:tower:") + 16


def test_the_finding_for_an_image_ranks_and_counts_like_a_hosts(cvedb):
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES)
    cves = matched(cvedb, [e])
    out = [f for f in di.evaluate(stored([e]), None, cves, TODAY) if f.rule == "docker.image_cves"]
    assert len(out) == 1
    f = out[0]
    assert f.severity == "high" and f.key == "nginx:1.27"
    assert f.title == "nginx:1.27 (Debian 12): 3 fixable CVEs, 1 known exploited"
    assert f.detail.index("CVE-2026-111497") < f.detail.index("CVE-2016-5180")                      # KEV first, as on a host
    assert "exploited, CISA KEV" in f.detail and "1 more in the image have no fix yet" in f.detail
    assert "Docker tab" not in f.detail and "Check for Updates" in f.howto and "apt upgrade" in f.howto and "does not help" in f.howto
    assert "newer image" in f.howto and f.link == f"/images#ci-{IDS['nginx'].removeprefix('sha256:')[:12]}"
    assert f.basis.startswith("nginx:") and not re.search(r"\d{4}-\d\d-\d\d", f.basis)


def test_unfixed_cves_alone_are_information_not_a_finding(cvedb):
    e = entry(IDS["nginx"], DEB12, [("edk2-ovmf", "edk2", "2020.1", ""), ("nodejs", "", "18.1", ""), ("libxml2", "", "2.9.14", "")])
    cves = matched(cvedb, [e])
    c = di.analyze(stored([e]), None, cves, TODAY)["rows"][0]["cve"]
    assert c["unfixed"] == 1 and c["fixable"] == [] and c["severity"] is None                       # minor ones are not counted at all
    assert [f for f in di.evaluate(stored([e]), None, cves, TODAY) if f.rule == "docker.image_cves"] == []


def test_a_fixable_cve_without_kev_or_a_high_score_is_medium_and_the_threshold_moves_it(cvedb):
    e = entry(IDS["nginx"], DEB12, [("libc-ares2", "c-ares", "1.10.0-1", "")])
    cves = matched(cvedb, [e])
    f = [x for x in di.evaluate(stored([e]), None, cves, TODAY) if x.rule == "docker.image_cves"][0]
    assert f.severity == "medium" and f.title == "nginx:1.27 (Debian 12): 2 fixable CVEs"
    top = max((c["epss"] or 0) for c in cves["images"][e["image_id"]]["cves"])
    assert top < 0.10
    cves["epss_high"] = top / 2 if top else 0.0
    hot = [x for x in di.evaluate(stored([e]), None, cves, TODAY) if x.rule == "docker.image_cves"][0]
    assert hot.severity == "high" and "high exploit score" in hot.title


def test_an_updated_image_clears_the_finding_and_the_basis_moves_only_with_the_cves(cvedb):
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES)
    base = di.evaluate(stored([e]), None, matched(cvedb, [e]), TODAY)[0].basis
    # The same CVEs after an unrelated package changes, a different image id and a different read time: the same basis.
    e2 = entry(IDS["postgres"], DEB12, BOOKWORM_PACKAGES + [("zlib1g", "zlib", "1:1.2.13", "")], read_at=1_800_009_999)
    again = di.evaluate(stored([e2], containers=[{"name": "web", "image": "nginx:1.27", "image_id": IDS["postgres"], "state": "running"}]), None, matched(cvedb, [e2]), TODAY)[0]
    assert again.basis == base and again.key == "nginx:1.27"
    # Fewer fixable CVEs: a new basis, so an acceptance comes back as Changed.
    e3 = entry(IDS["nginx"], DEB12, [p for p in BOOKWORM_PACKAGES if p[1] != "brotli"])
    assert di.evaluate(stored([e3]), None, matched(cvedb, [e3]), TODAY)[0].basis != base
    # The image is updated past the fixed versions: nothing.
    fixed = entry(IDS["nginx"], DEB12, [("libbrotli1", "brotli", "1.0.9-2+deb12u1", ""), ("libc-ares2", "c-ares", "1.19.0-1", "")])
    assert [f for f in di.evaluate(stored([fixed]), None, matched(cvedb, [fixed]), TODAY) if f.rule == "docker.image_cves"] == []


def test_an_ubuntu_image_is_matched_and_an_ubuntu_or_alpine_release_without_data_matches_nothing(cvedb):
    ents = [entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES),
            entry(IDS["postgres"], os_("ubuntu", "22.04", "jammy"), BOOKWORM_PACKAGES),
            entry(IDS["widget-new"], os_("alpine", "3.22.1"), [("musl", "", "1.2.4", "")], manager="apk"),
            entry(IDS["debian"], os_("centos", "9", pretty="CentOS Stream 9"), None, error="packages not read: CentOS Stream 9 does not use dpkg or apk"),
            entry(IDS["gadget"], DEB12, None, error="not read: stopped"), entry(IDS["mystery"], DEB12, None, error="not read yet")]
    a = di.analyze(stored(ents), None, matched(cvedb, ents), TODAY)
    assert a["counts"] == {"read": 3, "stopped": 1, "waiting": 1, "failed": 0, "other_os": 1, "debian": 1, "ubuntu": 1, "alpine": 1}
    kinds = {r["id"]: r["kind"] for r in a["rows"]}
    assert kinds[IDS["postgres"]] == "ubuntu" and kinds[IDS["widget-new"]] == "alpine"
    assert [r["cve"]["state"] for r in a["rows"] if r["id"] == IDS["widget-new"]] == ["absent"]       # 3.22 is not in this fixture's secdb
    assert [r["cve"]["state"] for r in a["rows"] if r["id"] == IDS["postgres"]] == ["absent"]         # jammy is not in this fixture's OVAL data
    assert {f.key for f in di.evaluate(stored(ents), None, matched(cvedb, ents), TODAY) if f.rule == "docker.image_cves"} == {"nginx:1.27"}


def test_an_ubuntu_image_counts_what_apt_can_fix_and_shows_the_rest_apart(cvedb):
    e = entry(IDS["postgres"], UBU24, UBUNTU_PACKAGES)
    cves = matched(cvedb, [e])
    c = di.analyze(stored([e]), None, cves, TODAY)["rows"][0]
    assert c["kind"] == "ubuntu" and c["ubuntu_release"] == "noble" and c["cve"]["state"] == "matched"
    cv = c["cve"]
    assert {x["cve"] for x in cv["fixable"]} == {"CVE-2022-49043", "CVE-2006-10002"}                  # libxml2 and libxml-parser-perl
    assert [x["cve"] for x in cv["esm"]] == ["CVE-2012-1148"]                                          # libxmltok: only fixed in esm-apps
    assert cv["unfixed"] == 2 and cv["severity"] == "medium"                                          # CVE-2025-66382 and CVE-2002-2439 are open; the negligible ones are not counted
    f = [x for x in di.evaluate(stored([e]), None, cves, TODAY) if x.rule == "docker.image_cves"]
    assert len(f) == 1
    f = f[0]
    assert f.severity == "medium" and f.title == "postgres:17 (Ubuntu 24.04): 2 fixable CVEs" and f.key == "postgres:17"
    assert "Canonical's Ubuntu OVAL data" in f.detail and "Ubuntu priority" in f.detail and "Debian" not in f.detail
    assert "2 more in the image have no fix yet" in f.detail and "1 more are fixed only in Ubuntu Pro's ESM archives, which an image cannot use" in f.detail
    assert "CVE-2012-1148" not in f.detail.split("Top CVEs:")[1].split("more in the image")[0] and not re.search(r"\d{4}-\d\d-\d\d", f.basis)
    # ESM-only CVEs alone raise nothing: updating the image cannot take them.
    only = entry(IDS["postgres"], UBU24, [UBUNTU_PACKAGES[2]])
    assert [x for x in di.evaluate(stored([only]), None, matched(cvedb, [only]), TODAY) if x.rule == "docker.image_cves"] == []
    assert di.analyze(stored([only]), None, matched(cvedb, [only]), TODAY)["rows"][0]["cve"]["esm"][0]["cve"] == "CVE-2012-1148"
    # The image is rebuilt on updated packages: the finding clears.
    new = entry(IDS["postgres"], UBU24, [("libxml2", "", "2.9.14+dfsg-1.3ubuntu3.1", ""), ("libxml-parser-perl", "", "2.47-1ubuntu0.24.04.1", "")])
    assert [x for x in di.evaluate(stored([new]), None, matched(cvedb, [new]), TODAY) if x.rule == "docker.image_cves"] == []
    # A known exploited CVE makes it high, and the ranking puts it first.
    cvedb.execute("INSERT INTO kev VALUES ('CVE-2022-49043', 'x', 'libxml2', 'libxml2 test', '2026-01-01', 'Unknown')")
    hot = [x for x in di.evaluate(stored([e]), None, matched(cvedb, [e]), TODAY) if x.rule == "docker.image_cves"][0]
    assert hot.severity == "high" and hot.title == "postgres:17 (Ubuntu 24.04): 2 fixable CVEs, 1 known exploited" and hot.detail.index("CVE-2022-49043") < hot.detail.index("CVE-2006-10002")


def test_kernel_cves_do_not_apply_to_a_container_with_only_kernel_headers(cvedb):
    inv = di.pseudo_inventory(entry(IDS["nginx"], DEB12, [("linux-libc-dev", "linux", "6.1.0-1", "")]))
    assert match._kernel_installed("linux", inv["sources"][0][2]) is False


def test_without_the_cve_chore_an_image_is_pending_and_with_cve_off_it_says_so():
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES)
    assert di.analyze(stored([e]), None, None, TODAY)["rows"][0]["cve"] == {"state": "off"}
    pending = {"enabled": True, "available": False, "epss_high": 0.1, "images": {}}
    assert di.analyze(stored([e]), None, pending, TODAY)["rows"][0]["cve"] == {"state": "pending"}
    assert di.evaluate(stored([e]), None, pending, TODAY) == []


# --- the chore and the poll, end to end ----------------------------------------------------------------------------------------------

def run_chore(hub_cfg, tmp_path, at, client=None):
    state = conn_of(hub_cfg)
    try:
        asyncio.run(run.Chore(hub_cfg, state, client or serve(tmp_path)).run_once(at))
    finally:
        state.close()


def seeded_world(world, tmp_path, entries):
    add_system(world)
    world.reader.summary = summary_with(entries)
    world.poll(time.time())
    run_chore(world.cfg, tmp_path, time.time())
    return world


def image_entries(extra=()):
    return [entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES, container="web"),
            entry(IDS["postgres"], UBU24, UBUNTU_PACKAGES, container="db"),
            entry(IDS["widget-new"], os_("alpine", "3.17.2"), [("musl", "", "1.2.4", "")], manager="apk", container="widget"),
            entry(IDS["inuse2"], DEB12, None, error="not read: stopped", container=None, read_at=None), *extra]


def finding_rows(world):
    conn = conn_of(world.cfg)
    try:
        return {(r["rule"], r["key"]): r for r in db.open_findings(conn, "tower") if r["rule"].startswith("docker.")}
    finally:
        conn.close()


def test_the_chore_matches_each_debian_and_alpine_image_under_a_pseudo_host_and_the_poll_opens_the_findings(world, tmp_path):
    seeded_world(world, tmp_path, image_entries())
    cdb = cvestore.connect_reader(world.cfg.cve_db_path)
    hosts = {r["host"] for r in cdb.execute("SELECT host FROM matched")}
    assert hosts == {di.pseudo_host("tower", IDS["nginx"]), di.pseudo_host("tower", IDS["postgres"]), di.pseudo_host("tower", IDS["widget-new"])}    # no real host has a colon in its id
    assert cdb.execute("SELECT COUNT(*) FROM ubu WHERE release = 'noble'").fetchone()[0] > 0 and cdb.execute("SELECT COUNT(*) FROM ubu WHERE release != 'noble'").fetchone()[0] == 0
    assert {r["name"] for r in cdb.execute("SELECT name FROM feed WHERE name LIKE 'ubuntu-%'")} == {"ubuntu-noble"}          # only the release an image runs is downloaded
    assert {r["source"] for r in cdb.execute("SELECT source FROM match WHERE host = ?", (di.pseudo_host("tower", IDS["postgres"]),))} == {"libxml2", "libxml-parser-perl", "libxmltok", "gcc-mingw-w64"}
    assert cdb.execute("SELECT COUNT(*) FROM deb WHERE release = 'bookworm'").fetchone()[0] > 0
    assert cdb.execute("SELECT COUNT(*) FROM apk WHERE release = 'v3.17'").fetchone()[0] > 0           # only the release an image runs is downloaded
    assert {r["name"] for r in cdb.execute("SELECT name FROM feed WHERE name LIKE 'alpine-%'")} == {"alpine-v3.17-main", "alpine-v3.17-community"}
    assert [r["source"] for r in cdb.execute("SELECT source FROM match WHERE host = ?", (di.pseudo_host("tower", IDS["widget-new"]),))] == ["musl"]
    cdb.close()
    world.poll(time.time() + 700)                                            # the next poll evaluates with the matches
    f = finding_rows(world)
    mine = {k for k in f if k[0] in ("docker.eol_base", "docker.image_cves")}
    assert mine == {("docker.eol_base", "all"), ("docker.image_cves", "nginx:1.27"), ("docker.image_cves", "postgres:17"), ("docker.image_cves", "ghcr.io/acme/widget:latest")}
    assert f[("docker.image_cves", "postgres:17")]["severity"] == "medium" and f[("docker.image_cves", "postgres:17")]["title"] == "postgres:17 (Ubuntu 24.04): 2 fixable CVEs"
    assert f[("docker.image_cves", "nginx:1.27")]["severity"] == "high" and f[("docker.eol_base", "all")]["severity"] == "medium"
    wd = f[("docker.image_cves", "ghcr.io/acme/widget:latest")]
    assert wd["severity"] == "medium" and wd["title"] == "ghcr.io/acme/widget:latest (Alpine 3.17): 1 fixable CVE"
    assert ("docker.unused_volumes", "all") in f                              # the storage findings are untouched
    conn = conn_of(world.cfg)
    assert not [r for r in db.open_findings(conn, "tower") if r["rule"].startswith("cve.")]       # no host-style cve finding for an image
    assert not conn.execute("SELECT 1 FROM hosts WHERE id LIKE 'docker:%'").fetchone()
    conn.close()


# --- the page --------------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def page(web, tmp_path):
    web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, reader_token=TOKEN))
    web.reader.summary = summary_with(image_entries())
    web.poll(time.time())
    run_chore(web.cfg, tmp_path, time.time())
    web.poll(time.time() + 700)
    return web


def test_the_page_lists_each_image_with_its_os_support_packages_and_cves(page):
    html = page.client.get("/h/tower/images").text
    assert "Container images" in html and 'id="image-list"' in html and 'id="image-coverage"' in html
    table = html.split('data-table="container-images"')[1].split("</table>")[0]
    rows = {m.group(1): m.group(0) for m in re.finditer(r'<tr id="(ci-[^"]+)" data-row>.*?</tr>', table, re.S)}
    assert len(rows) == 4
    nginx = rows["ci-" + IDS["nginx"].removeprefix("sha256:")[:12]]
    assert "nginx:1.27" in nginx and "Debian 12" in nginx and "bookworm" in nginx and "LTS until 2028-06-30" in nginx
    assert "3 fixable" in nginx and "1 exploited (KEV)" in nginx and "1 with no fix yet" in nginx and "3 read" not in nginx and "6 read" in nginx
    assert "dpkg" in nginx and 'data-status-label="unexpected"' in nginx
    pg = rows["ci-" + IDS["postgres"].removeprefix("sha256:")[:12]]
    assert "Ubuntu 24.04" in pg and "phase 3b" not in pg and "not built yet" not in pg and "2 fixable" in pg
    assert "2 with no fix yet" in pg and "1 fixed only in Ubuntu Pro (ESM)" in pg and 'data-status-label="unexpected"' in pg
    wd = rows["ci-" + IDS["widget-new"].removeprefix("sha256:")[:12]]
    assert "Alpine 3.17" in wd and "End of life since 2024-11-22" in wd and "1 fixable" in wd and "Alpine matching next" not in wd
    assert "no fix yet" not in wd and 'data-status-label="unexpected"' in wd
    assert "CVE-2026-74860" in html and "security.alpinelinux.org/vuln/CVE-2026-74860" in html and "https://secdb.alpinelinux.org/v3.17/" in html
    assert "ubuntu.com/security/CVE-2022-49043" in html and "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2" in html
    assert "docker cp -L db:/var/lib/dpkg/status - | tar -xO" in html and "pro security-status" in html and "apt list --upgradable" in html
    assert "apk version -l &#39;&lt;&#39;" in html or "apk version -l '&lt;'" in html
    st = rows["ci-" + IDS["inuse2"].removeprefix("sha256:")[:12]]
    assert "Not read: stopped" in st and "—" in st
    # Phone layout: every cell has its label; each row has a source panel naming the endpoint's CLI.
    for row in rows.values():
        assert row.count("data-label=") == 6 and "popover" in row
    assert "docker cp -L web:/var/lib/dpkg/status - | tar -xO" in html and "docker cp -L widget:/lib/apk/db/installed - | tar -xO" in html
    assert f"GET {READER}/v1/summary, field image_packages" in html and "ContainerArchive" in html
    assert "CVE-2026-111497" in html and "security-tracker.debian.org/tracker/CVE-2026-111497" in html
    assert TOKEN not in html and check_panels(html) >= 5


def test_the_coverage_card_counts_what_is_not_matched(page):
    html = page.client.get("/h/tower/images").text
    cov = html.split('id="image-coverage"')[1]
    assert "3 of 4 images have a package list" in cov and "CVEs are matched for Debian, Ubuntu and Alpine images." in cov
    assert "Debian: 1 image matched" in cov and "Ubuntu: 1 image matched against Canonical's Ubuntu OVAL data" in cov and "phase 3b" not in cov and "Alpine matching next" not in cov
    assert "Ubuntu 24.04: OVAL data checked" in cov and "ESM archives" in cov
    assert "Alpine: 1 image matched against Alpine's security database (secdb)" in cov and "no count of CVEs without a fix" in cov
    assert "Alpine 3.17: secdb data checked" in cov
    assert "used only by stopped containers: not read" in cov


def test_the_page_before_a_reader_with_an_old_reader_and_with_cve_matching_off(web, tmp_path):
    web.client.post("/remotes/new", data=form(action="save"))
    web.poll()
    html = web.client.get("/h/tower/images").text
    assert 'id="image-list"' in html and 'id="image-coverage"' in html and "not read for this system" in html and 'href="/remotes/tower/edit#docker-reader"' in html
    web.client.post("/remotes/tower/edit", data=form(action="save", enabled="1", key="", reader_on="1", reader_url=READER, reader_token=TOKEN))
    web.poll(time.time() + 100)                                               # the standard summary has no image_packages: an old reader
    html = web.client.get("/h/tower/images").text
    assert "does not send package lists yet" in html and "Update its container" in html
    web.reader.summary = summary_with(image_entries())
    web.poll(time.time() + 1000)
    html = web.client.get("/h/tower/images").text
    assert "Waiting for the CVE matcher" in html and "Docker 12" not in html          # the chore has not matched anything yet


def test_the_overview_and_the_report_carry_the_findings(page):
    ov = page.client.get("/h/tower/").text
    assert "Container images" in ov and 'href="/h/tower/images"' in ov and "1 on an end-of-life OS, 3 with fixable CVEs" in ov
    assert "1 container image runs on an end-of-life OS" in ov and "nginx:1.27 (Debian 12): 3 fixable CVEs, 1 known exploited" in ov
    rep = page.client.get("/h/tower/report.md").text
    assert "nginx:1.27" in rep and "3 fixable CVEs, 1 known exploited" in rep and "apt upgrade" in rep


def test_a_row_is_accepted_from_its_panel_stays_accepted_and_clears_when_the_image_is_updated(page, tmp_path):
    r = page.client.post("/h/tower/findings/accept", data={"rule": "docker.image_cves", "key": "nginx:1.27", "note": "patched next week", "next": "/h/tower/images"})
    assert r.status_code == 303
    row_id = "ci-" + IDS["nginx"].removeprefix("sha256:")[:12]

    def row():
        return re.search(r'<tr id="' + row_id + r'" data-row>.*?</tr>', page.client.get("/h/tower/images").text, re.S).group(0)
    assert 'data-status-label="accepted"' in row() and "patched next week" in row() and "3 fixable" in row()     # accepted items stay visible
    # Another poll with the same CVEs keeps it accepted: the basis has no dates or counts.
    page.poll(time.time() + 2000)
    assert 'data-status-label="accepted"' in row()
    # The image is updated past the fixed versions (read again, so a new read time): the finding goes and the row says none.
    fixed = [("libbrotli1", "brotli", "1.0.9-2+deb12u1", ""), ("libc-ares2", "c-ares", "1.19.0-1", "")]
    ents = image_entries()
    ents[0] = entry(IDS["nginx"], DEB12, fixed, container="web", read_at=1_800_050_000)
    page.reader.summary = summary_with(ents)
    page.poll(time.time() + 4000)
    run_chore(page.cfg, tmp_path, time.time() + 4000)
    page.poll(time.time() + 8000)
    assert ("docker.image_cves", "nginx:1.27") not in finding_rows(page)
    assert "None fixable" in row()


# --- Alpine images (secdb) -------------------------------------------------------------------------------------------------------

ALP323 = os_("alpine", "3.23.2", pretty="Alpine Linux v3.23")
# openssl's subpackages, brotli's, musl; busybox, zlib and c-ares are at or past their fixed versions. The fixture's CVEs are
# openssl CVE-2023-31124 and CVE-2026-11979 (fixed in 3.1.4-r2), brotli CVE-2026-111497 (on KEV) and musl CVE-2026-74860.
ALPINE_PACKAGES = [("libcrypto3", "openssl", "3.1.4-r0", ""), ("libssl3", "openssl", "3.1.4-r0", ""), ("openssl", "", "3.1.4-r0", ""),
                   ("brotli-libs", "brotli", "1.1.0-r0", ""), ("musl", "", "1.2.4_git20230717-r4", ""),
                   ("busybox", "", "1.36.1-r5", ""), ("zlib", "", "1.3.1-r1", ""), ("c-ares", "", "1.28.1-r0", "")]


def alpine_entry(packages=ALPINE_PACKAGES, os_info=ALP323, iid="widget-new"):
    return entry(IDS[iid], os_info, packages, manager="apk", container="widget")


def alpine_findings(cves, e):
    return [f for f in di.evaluate(stored([e]), None, cves, TODAY) if f.rule == "docker.image_cves"]


def test_the_pseudo_inventory_of_an_alpine_image_has_one_version_per_origin_and_says_when_it_picked_the_lowest():
    inv = di.pseudo_inventory(alpine_entry(ALPINE_PACKAGES + [("openssl-dev", "openssl", "3.1.4-r1", ""), ("odd", "odd", "1.0bc", "")]))
    srcs = {s: (v, b) for s, v, b in inv["sources"]}
    assert srcs["openssl"] == ("3.1.4-r0", ["libcrypto3", "libssl3", "openssl", "openssl-dev"])       # the lowest of r0 and r1
    assert srcs["brotli"] == ("1.1.0-r0", ["brotli-libs"]) and "odd" not in srcs                      # a version apk cannot parse is left out
    assert inv["backend"] == "apk" and inv["os_id"] == "alpine" and inv["release"] == "v3.23" and match.release_of(inv) is None
    assert "1 origin has subpackages at different versions, matched at the lowest (openssl)" in inv["note"]
    assert "1 package has a version apk cannot parse and was skipped" in inv["note"]
    same = di.pseudo_inventory(alpine_entry())
    assert same["note"] == "" and same["hash"] != inv["hash"]
    assert di.pseudo_inventory(alpine_entry(os_info=os_("alpine", "3.23.2", "", ""))) ["release"] == "v3.23"


def test_an_alpine_image_gets_a_ranked_finding_with_no_unfixed_count(cvedb):
    e = alpine_entry()
    cves = matched(cvedb, [e])
    assert cves["images"][e["image_id"]]["note"] == ""
    a = di.analyze(stored([e]), None, cves, TODAY)
    row = a["rows"][0]
    assert row["kind"] == "alpine" and row["alpine_release"] == "v3.23" and row["cve"]["state"] == "matched"
    assert [c["cve"] for c in row["cve"]["fixable"]][0] == "CVE-2026-111497" and row["cve"]["unfixed"] == 0 and len(row["cve"]["fixable"]) == 4
    (f,) = alpine_findings(cves, e)
    assert f.severity == "high" and f.key == "ghcr.io/acme/widget:latest"
    assert f.title == "ghcr.io/acme/widget:latest (Alpine 3.23): 4 fixable CVEs, 1 known exploited"
    assert "Alpine's security database (secdb)" in f.detail and "Debian" not in f.detail and "no fix yet" not in f.detail
    assert f.detail.index("CVE-2026-111497") < f.detail.index("CVE-2026-74860") and "exploited, CISA KEV" in f.detail
    assert "apk upgrade" in f.howto and "apt" not in f.howto and "Check for Updates" in f.howto
    assert f.link == f"/images#ci-{IDS['widget-new'].removeprefix('sha256:')[:12]}" and f.basis.startswith("ghcr.io/acme/widget:")
    assert not re.search(r"\d{4}-\d\d-\d\d", f.basis)
    # Severity follows the same rule as a Debian image: without KEV or a high score it is Medium, and the threshold moves it.
    only = alpine_entry([("musl", "", "1.2.4_git20230717-r4", "")])
    c2 = matched(cvedb, [only])
    (m,) = alpine_findings(c2, only)
    assert m.severity == "medium" and m.title == "ghcr.io/acme/widget:latest (Alpine 3.23): 1 fixable CVE"
    c2["epss_high"] = 0.001
    assert alpine_findings(c2, only)[0].severity == "high"


def test_an_alpine_finding_clears_when_the_image_is_updated_and_its_basis_moves_with_the_cves(cvedb):
    e = alpine_entry()
    base = alpine_findings(matched(cvedb, [e]), e)[0].basis
    # The same CVEs after an unrelated package changes: the same basis (an acceptance stays).
    e2 = alpine_entry(ALPINE_PACKAGES + [("tzdata", "", "2025a-r0", "")])
    assert alpine_findings(matched(cvedb, [e2]), e2)[0].basis == base
    # One origin fixed: fewer CVEs, a new basis.
    e3 = alpine_entry([p for p in ALPINE_PACKAGES if p[1] != "openssl" and p[0] != "openssl"])
    (f3,) = alpine_findings(matched(cvedb, [e3]), e3)
    assert f3.basis != base and "2 fixable CVEs" in f3.title
    # Updated past every fixed version: nothing, and the row says so.
    fixed = alpine_entry([("libcrypto3", "openssl", "3.1.4-r2", ""), ("brotli-libs", "brotli", "1.1.0-r1", ""), ("musl", "", "1.2.4_git20230717-r5", "")])
    cves = matched(cvedb, [fixed])
    assert alpine_findings(cves, fixed) == []
    assert di.analyze(stored([fixed]), None, cves, TODAY)["rows"][0]["cve"]["fixable"] == []
    # A release whose secdb has a newer version than any in the image but an equal one: equal is fixed, not vulnerable.
    equal = alpine_entry([("libcrypto3", "openssl", "3.1.4-r2", "")])
    assert alpine_findings(matched(cvedb, [equal]), equal) == []


def test_subpackages_at_different_versions_match_at_the_lowest_and_the_row_says_so(cvedb):
    e = alpine_entry([("libcrypto3", "openssl", "3.1.4-r2", ""), ("libssl3", "openssl", "3.1.4-r0", "")])
    cves = matched(cvedb, [e])
    assert "subpackages at different versions" in cves["images"][e["image_id"]]["note"]
    row = di.analyze(stored([e]), None, cves, TODAY)["rows"][0]
    assert len(row["cve"]["fixable"]) == 2 and "matched at the lowest (openssl)" in row["cve"]["note"]


def test_an_alpine_release_secdb_lacks_or_an_edge_image_is_not_a_finding_and_says_why(cvedb):
    for os_info, state in ((os_("alpine", "3.99.1"), "absent"), (os_("alpine", "3.24.0_alpha20260101"), "unmapped")):
        e = alpine_entry(os_info=os_info)
        cves = matched(cvedb, [e])
        row = di.analyze(stored([e]), None, cves, TODAY)["rows"][0]
        assert row["kind"] == "alpine" and row["cve"]["state"] == state
        assert alpine_findings(cves, e) == []
    assert di.analyze(stored([alpine_entry(os_info=os_("alpine", "3.99.1"))]), None, matched(cvedb, [alpine_entry(os_info=os_("alpine", "3.99.1"))]), TODAY)["rows"][0]["cve"]["label"] == "Alpine 3.99"


def test_alpine_images_wait_for_secdb_and_follow_the_cve_switch():
    e = alpine_entry()
    assert di.analyze(stored([e]), None, None, TODAY)["rows"][0]["cve"] == {"state": "off"}
    pending = {"enabled": True, "available": True, "epss_high": 0.1, "alpine": {"v3.23": {"state": "pending", "ok_at": None, "error": None}}, "images": {}}
    assert di.analyze(stored([e]), None, pending, TODAY)["rows"][0]["cve"] == {"state": "pending"}
    assert alpine_findings(pending, e) == []


@pytest.fixture
def page_with(web, tmp_path):
    def build(entries, client=None):
        web.client.post("/remotes/new", data=form(action="save", reader_on="1", reader_url=READER, reader_token=TOKEN))
        web.reader.summary = summary_with(entries)
        web.poll(time.time())
        run_chore(web.cfg, tmp_path, time.time(), client)
        web.poll(time.time() + 700)
        return web
    return build


def test_the_page_says_when_secdb_has_no_file_for_a_release_and_for_an_edge_image(page_with):
    ents = [entry(IDS["widget-new"], os_("alpine", "3.9.6"), [("musl", "", "1.1.0", "")], manager="apk", container="widget"),
            entry(IDS["tool"], os_("alpine", "3.24.0_alpha20260101"), [("musl", "", "1.2.5", "")], manager="apk", container="tool")]
    w = page_with(ents)
    html = w.client.get("/h/tower/images").text
    cov = html.split('id="image-coverage"')[1].replace("&#39;", "'")
    assert "Alpine 3.9: not in Alpine's security database, so nothing is matched for it" in cov and "Alpine: 2 images matched" in cov
    table = html.split('data-table="container-images"')[1].split("</table>")[0].replace("&#39;", "'")
    assert "Alpine 3.9: not in Alpine's security database" in table
    assert "Release not named (edge?): not matched" in html
    assert not [k for k in finding_rows(w) if k[0] == "docker.image_cves"]
    # The 404 is an answer: the hub holds no error for it.
    conn = cvestore.connect_reader(w.cfg.cve_db_path)
    assert {r["status"] for r in conn.execute("SELECT status FROM feed WHERE name LIKE 'alpine-v3.9-%'")} == {"absent"}
    conn.close()


def test_the_page_shows_an_error_line_when_secdb_cannot_be_downloaded(page_with, tmp_path):
    down = serve(tmp_path, override={feeds.ALPINE_HOST: lambda r: httpx.Response(503)})
    w = page_with([alpine_entry(os_info=os_("alpine", "3.17.2"))], down)
    html = w.client.get("/h/tower/images").text
    cov = html.split('id="image-coverage"')[1]
    assert "Alpine 3.17: secdb data not downloaded yet" in cov and "The last download failed (HTTP 503); there is no copy yet" in cov
    assert "Waiting for the CVE matcher" in html


def test_the_vulnerabilities_pages_data_feeds_list_the_secdb_files(page_with, tmp_path):
    w = page_with([alpine_entry(os_info=os_("alpine", "3.17.2"))])
    cdb = cvestore.connect_reader(w.cfg.cve_db_path)
    from daemonsight.web import views
    rows = views._feed_rows(cdb, time.time(), 24)
    cdb.close()
    names = [r["name"] for r in rows]
    assert names[:3] == ["debian", "epss", "kev"] and names[3:] == ["alpine-v3.17-community", "alpine-v3.17-main"]
    main = rows[-1]
    assert main["title"] == "Alpine security database v3.17 main" and main["state"] == "Up to date" and main["alpine"] and main["rows"] > 0
    assert main["src"]["entries"][0]["text"] == "https://secdb.alpinelinux.org/v3.17/main.json" and "Attribution-ShareAlike 4.0" in main["terms"]
