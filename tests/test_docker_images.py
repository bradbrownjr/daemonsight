"""Container images: the base OS and its end of life (docker.eol_base), Debian CVE matching (docker.image_cves) and the
Container images page. Everything is synthetic: nginx, debian and alpine are public names, the rest is made up."""

import asyncio
import copy
import re
import time
from datetime import date

import pytest

from daemonsight import db, distro
from daemonsight.cve import feeds, match, run, store as cvestore
from daemonsight.remote import docker_images as di
from daemonsight.remote import docker_storage as ds

from .fake_docker import IDS, standard_summary
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
    feeds.load_epss(conn, epss_gz(tmp_path))
    feeds.load_kev(conn, kev_gz(tmp_path))
    yield conn
    conn.close()


def matched(cvedb, entries, host="tower"):
    """What the chore does for images (matching under pseudo-host ids), then what load_cves gives the rules."""
    out = {}
    for e in entries:
        inv = di.pseudo_inventory(e)
        if inv:
            match.match_host(cvedb, di.pseudo_host(host, e["image_id"]), inv, "g")
            out[e["image_id"]] = {"matched": True, "cves": match.host_cves(cvedb, di.pseudo_host(host, e["image_id"]), ("fix", "nofix"))}
    return {"enabled": True, "available": True, "epss_high": 0.10, "feed_at": 1.0, "images": out}


def test_the_pseudo_inventory_groups_by_source_and_source_version_and_only_for_debian():
    e = entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES + [("libbrotli-dev", "brotli", "1.0.9-2", "")])
    inv = di.pseudo_inventory(e)
    srcs = {s: (v, b) for s, v, b in inv["sources"]}
    assert srcs["brotli"] == ("1.0.9-2", ["libbrotli-dev", "libbrotli1"]) and srcs["openssl"] == ("3.0.11-1", ["libssl3"])   # the source's version, not the binary's +b1
    assert inv["os_id"] == "debian" and inv["codename"] == "bookworm" and inv["backend"] == "apt" and match.release_of(inv) == "bookworm"
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("ubuntu", "22.04", "jammy"), [("a", "", "1", "")])) is None
    assert di.pseudo_inventory(entry(IDS["nginx"], os_("alpine", "3.19"), [("a", "", "1", "")], manager="apk")) is None
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


def test_ubuntu_alpine_and_the_rest_are_counted_and_never_findings(cvedb):
    ents = [entry(IDS["nginx"], DEB12, BOOKWORM_PACKAGES),
            entry(IDS["postgres"], os_("ubuntu", "22.04", "jammy"), BOOKWORM_PACKAGES),
            entry(IDS["widget-new"], os_("alpine", "3.22.1"), [("musl", "", "1.2.4", "")], manager="apk"),
            entry(IDS["debian"], os_("centos", "9", pretty="CentOS Stream 9"), None, error="packages not read: CentOS Stream 9 does not use dpkg or apk"),
            entry(IDS["gadget"], DEB12, None, error="not read: stopped"), entry(IDS["mystery"], DEB12, None, error="not read yet")]
    a = di.analyze(stored(ents), None, matched(cvedb, ents), TODAY)
    assert a["counts"] == {"read": 3, "stopped": 1, "waiting": 1, "failed": 0, "other_os": 1, "debian": 1, "ubuntu": 1, "alpine": 1}
    kinds = {r["id"]: r["kind"] for r in a["rows"]}
    assert kinds[IDS["postgres"]] == "ubuntu" and kinds[IDS["widget-new"]] == "alpine"
    assert {f.key for f in di.evaluate(stored(ents), None, matched(cvedb, ents), TODAY) if f.rule == "docker.image_cves"} == {"nginx:1.27"}


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

def run_chore(hub_cfg, tmp_path, at):
    state = conn_of(hub_cfg)
    try:
        asyncio.run(run.Chore(hub_cfg, state, serve(tmp_path)).run_once(at))
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
            entry(IDS["postgres"], os_("ubuntu", "22.04", "jammy"), BOOKWORM_PACKAGES, container="db"),
            entry(IDS["widget-new"], os_("alpine", "3.17.2"), [("musl", "", "1.2.4", "")], manager="apk", container="widget"),
            entry(IDS["inuse2"], DEB12, None, error="not read: stopped", container=None, read_at=None), *extra]


def finding_rows(world):
    conn = conn_of(world.cfg)
    try:
        return {(r["rule"], r["key"]): r for r in db.open_findings(conn, "tower") if r["rule"].startswith("docker.")}
    finally:
        conn.close()


def test_the_chore_matches_each_debian_image_under_a_pseudo_host_and_the_poll_opens_the_findings(world, tmp_path):
    seeded_world(world, tmp_path, image_entries())
    cdb = cvestore.connect_reader(world.cfg.cve_db_path)
    hosts = {r["host"] for r in cdb.execute("SELECT host FROM matched")}
    assert hosts == {di.pseudo_host("tower", IDS["nginx"])}                  # Debian only; no real host has a colon in its id
    assert cdb.execute("SELECT COUNT(*) FROM deb WHERE release = 'bookworm'").fetchone()[0] > 0
    cdb.close()
    world.poll(time.time() + 700)                                            # the next poll evaluates with the matches
    f = finding_rows(world)
    mine = {k for k in f if k[0] in ("docker.eol_base", "docker.image_cves")}
    assert mine == {("docker.eol_base", "all"), ("docker.image_cves", "nginx:1.27")}
    assert f[("docker.image_cves", "nginx:1.27")]["severity"] == "high" and f[("docker.eol_base", "all")]["severity"] == "medium"
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
    assert "Ubuntu 22.04" in pg and "Ubuntu matching not built yet (phase 3b)" in pg and "fixable" not in pg.replace("Fixable", "")
    wd = rows["ci-" + IDS["widget-new"].removeprefix("sha256:")[:12]]
    assert "Alpine 3.17" in wd and "End of life since 2024-11-22" in wd and "Alpine matching next" in wd and 'data-status-label="unexpected"' in wd
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
    assert "3 of 4 images have a package list" in cov
    assert "Debian: 1 image matched" in cov and "Ubuntu matching not built yet (phase 3b)" in cov and "Alpine matching next" in cov
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
    assert "Container images" in ov and 'href="/h/tower/images"' in ov and "1 on an end-of-life OS, 1 with fixable CVEs" in ov
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
