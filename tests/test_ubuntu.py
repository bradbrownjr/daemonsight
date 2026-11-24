"""Ubuntu CVE matching (cve/ubuntu.py): Canonical's OVAL parser on trimmed real data, version order, the release mapping, the
download, the loader, the matching of a host and the findings, and the collector's Ubuntu inventory. The two OVAL files in
tests/fixtures/cve (ubuntu-noble.oval.xml and ubuntu-focal.oval.xml) are verbatim definitions from Canonical's files of
2026-11-24 with the long kernel lists cut; the EPSS and KEV rows added by the tests are made up."""

import asyncio
import bz2
import io
import random
import re
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from daemonsight import db
from daemonsight.collector.sources import inventory as inv
from daemonsight.config import Config
from daemonsight.cve import debver, exposure, feeds, match, run, store, ubuntu

from .test_cve import DAY, FIX, epss_gz, kev_gz, put_inventory, serve  # noqa: F401
from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)
from .test_web import seeded  # noqa: F401 (fixture)


def oval_bz2(tmp_path: Path, release: str) -> Path:
    p = tmp_path / f"ubuntu-{release}.oval.xml.bz2"
    p.write_bytes(bz2.compress((FIX / f"ubuntu-{release}.oval.xml").read_bytes()))
    return p


def loaded(tmp_path: Path, kernels=frozenset({"linux", "linux-aws"}), releases=("noble", "focal")):
    """A cve.db with the trimmed OVAL files loaded."""
    conn = store.connect(tmp_path / "cve.db")
    for rel in releases:
        feeds.load_ubuntu(conn, oval_bz2(tmp_path, rel), feeds.ubuntu_feed(rel), set(kernels))
    return conn


def ubuntu_inv(sources, codename="noble", version_id="24.04", esm=None, h="a1", taken_at=1.0):
    d = {"backend": "apt", "os_id": "ubuntu", "codename": codename, "version_id": version_id, "sources": sources, "hash": h,
         "taken_at": taken_at}
    if esm is not None:
        d["esm"] = esm
    return d


def rows_of(conn, host):
    return {(r["source"], r["cve"]): (r["state"], r["installed"], r["fixed"], r["urgency"])
            for r in conn.execute("SELECT * FROM match WHERE host = ?", (host,))}


# --- the release mapping -----------------------------------------------------------------------------------------------------

def test_a_host_is_matched_only_when_it_is_ubuntu_with_a_release_name():
    assert ubuntu.release_of(ubuntu_inv([])) == "noble"
    assert ubuntu.release_of(ubuntu_inv([], codename="jammy")) == "jammy"
    assert ubuntu.release_of({**ubuntu_inv([]), "os_id": "linuxmint", "codename": "wilma"}) is None      # a derivative with its own id
    assert ubuntu.release_of({**ubuntu_inv([]), "os_id": "debian"}) is None and match.release_of(ubuntu_inv([])) is None
    assert ubuntu.release_of({**ubuntu_inv([]), "codename": None}) is None
    assert ubuntu.release_of({**ubuntu_inv([]), "codename": "../noble"}) is None and ubuntu.release_of({**ubuntu_inv([]), "backend": "dnf"}) is None


def test_the_display_name_comes_from_the_release_data():
    assert ubuntu.display("noble") == "Ubuntu 24.04" and ubuntu.display("jammy", "22.04") == "Ubuntu 22.04"
    assert ubuntu.display("nosuchthing") == "Ubuntu nosuchthing" and ubuntu.display(None) == "Ubuntu"


@pytest.mark.parametrize("name", ["noble", "focal", "jammy"])
def test_the_url_of_a_release_is_the_one_file_for_it(name):
    f = feeds.ubuntu_feed(name)
    assert f.url == f"https://security-metadata.canonical.com/oval/com.ubuntu.{name}.cve.oval.xml.bz2" and f.name == f"ubuntu-{name}"
    assert f.hosts == ("security-metadata.canonical.com",) and f.kind == "ubuntu" and f.magic == b"BZh"
    assert "Attribution-ShareAlike 4.0" in f.terms and feeds.ubuntu_title(f.name) == f"Ubuntu CVE data ({name})" and feeds.ubuntu_title("kev") == "kev"


# --- parsing real data -------------------------------------------------------------------------------------------------------

def parsed(release):
    with open(FIX / f"ubuntu-{release}.oval.xml", "rb") as fh:
        return {cve: (prio, descr, sorted(rows)) for cve, prio, descr, rows in ubuntu.parse_oval(fh, release)}


def test_the_noble_definitions_give_fixed_open_esm_and_kernel_rows():
    got = parsed("noble")
    assert got["CVE-2006-10002"][0] == "medium"
    assert got["CVE-2006-10002"][2] == [("libxml-parser-perl", "", 0, "fixed", "2.47-1ubuntu0.24.04.1")]
    assert "Update Instructions" not in got["CVE-2006-10002"][1] and "pro fix" not in got["CVE-2006-10002"][1]            # Canonical's text after the CVE's is cut
    assert got["CVE-2006-10002"][1].startswith("XML::Parser versions through 2.45 for Perl")
    # One CVE across several packages and pockets: ordinary open rows, and the esm-apps pocket fixed with a +esm version.
    assert got["CVE-2012-1148"][2] == [("cadaver", "", 0, "open", None), ("libxmltok", "esm-apps", 0, "fixed", "1.2-4.1ubuntu2.24.0.4.1+esm3"),
                                       ("matanza", "", 0, "open", None), ("swish-e", "esm-apps", 0, "open", None)]
    assert got["CVE-2002-2439"][0] == "low" and {r[0] for r in got["CVE-2002-2439"][2]} == {"gcc-arm-none-eabi", "gcc-h8300-hms", "gcc-mingw-w64"}
    assert got["CVE-2008-5144"][0] == "negligible" and got["CVE-2024-26458"][0] == "negligible"
    # A kernel: one row per flavor, fixed with a version or open ("Is kernel 'linux-realtime' running?" alone).
    assert got["CVE-2020-12351"][2] == [("linux", "", 1, "fixed", "6.8.0-35.35"), ("linux-aws", "", 1, "fixed", "6.8.0-1009.9"),
                                         ("linux-azure", "", 1, "fixed", "6.8.0-1008.8")]
    assert ("linux-realtime", "", 1, "open", None) in got["CVE-2022-49034"][2] and ("linux", "", 1, "fixed", "6.8.0-58.60") in got["CVE-2022-49034"][2]
    # The inventory definition and anything not a CVE are not rows.
    assert not any(not c.startswith("CVE-") for c in got)


def test_the_focal_file_has_the_esm_infra_pocket():
    got = parsed("focal")
    assert got["CVE-2024-42516"][2] == [("apache2", "esm-infra", 0, "fixed", "2.4.41-4ubuntu3.23+esm2")]
    assert got["CVE-2019-17567"][2] == [("apache2", "esm-infra", 0, "open", None)]
    assert got["CVE-2012-1148"][2] == [("libxmltok", "esm-apps", 0, "fixed", "1.2-4ubuntu0.20.04.1~esm5"), ("swish-e", "esm-apps", 0, "open", None)]     # focal's esm-apps uses ~esm
    assert got["CVE-2016-3709"][2] == [("libxml2", "", 0, "fixed", "2.9.10+dfsg-5ubuntu0.20.04.4")]


def test_a_release_other_than_the_files_gives_no_rows_and_a_document_that_is_not_oval_is_refused():
    with open(FIX / "ubuntu-noble.oval.xml", "rb") as fh:
        assert [r for _c, _p, _d, rows in ubuntu.parse_oval(fh, "focal") for r in rows if not r[2]] == []        # every package criterion names noble
    for bad in (b"<html/>", b"", b"<oval_definitions xmlns='x'/>", b"not xml"):
        with pytest.raises((ubuntu.OvalError, ValueError)):
            list(ubuntu.parse_oval(io.BytesIO(bad), "noble"))


def test_junk_in_a_definition_is_skipped_not_kept():
    ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    def doc(defs):
        return (f'<oval_definitions xmlns="{ns}"><definitions>{defs}</definitions><tests/></oval_definitions>').encode()

    def d(cve, comments, prio="high"):
        crit = "".join(f'<criterion test_ref="t" comment="{c}"/>' for c in comments)
        return (f'<definition id="x" class="vulnerability"><metadata><reference source="CVE" ref_id="{cve}"/>'
                f'<description>text</description><advisory><cve priority="{prio}"/></advisory></metadata><criteria>{crit}</criteria></definition>')
    good = "bash source package in noble, is affected and has been fixed (note: '5.2.21-2ubuntu4.1')."
    rows = list(ubuntu.parse_oval(io.BytesIO(doc(
        d("CVE-2026-0001", [good]) + d("not-a-cve", [good]) + d("CVE-2026-0002", ["bad name! source package in noble, might be affected and may need fixing."])
        + d("CVE-2026-0003", ["bash source package in noble, is affected and has been fixed (note: '1.0-').", "x source package in fips/noble, might be affected and may need fixing."])
        + d("CVE-2026-0004", ["bash source package in noble, something else."]) + d("CVE-2026-0005", ["zsh source package in jammy, might be affected and may need fixing."])
        + d("CVE-2026-0006", ["curl source package in noble, might be affected and may need fixing."], prio="bogus")
        + d("CVE-2026-0007", ["perl source package in esm-weird/noble, might be affected and may need fixing."]))), "noble"))
    assert [(c, p, r) for c, p, _d, r in rows] == [("CVE-2026-0001", "high", [("bash", "", 0, "fixed", "5.2.21-2ubuntu4.1")]),
                                                   ("CVE-2026-0006", "", [("curl", "", 0, "open", None)]),
                                                   ("CVE-2026-0007", "high", [("perl", "esm-weird", 0, "open", None)])]


def test_a_file_that_decodes_to_far_more_than_it_should_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(ubuntu, "MAX_BYTES", 5000)
    p = oval_bz2(tmp_path, "noble")
    with pytest.raises(ubuntu.OvalError, match="size limit"):
        list(ubuntu.load_file(p, "noble"))


# --- loading ----------------------------------------------------------------------------------------------------------------

def test_loading_keeps_kernel_rows_only_for_the_flavors_asked_for_and_replaces_one_release_at_a_time(tmp_path):
    conn = loaded(tmp_path, kernels={"linux"})
    kern = {r[0] for r in conn.execute("SELECT DISTINCT source FROM ubu WHERE release = 'noble' AND kernel = 1")}
    assert kern == {"linux"} and conn.execute("SELECT COUNT(*) FROM ubu WHERE kernel = 0 AND release = 'noble'").fetchone()[0] > 10
    assert store.get_meta(conn, "ubu_kernels_noble") == '["linux"]'
    n = conn.execute("SELECT COUNT(*) FROM ubu WHERE release = 'focal'").fetchone()[0]
    path = oval_bz2(tmp_path, "noble")
    rows, note = feeds.load_ubuntu(conn, path, feeds.ubuntu_feed("noble"), {"linux", "linux-aws", "linux-realtime"})
    assert {r[0] for r in conn.execute("SELECT DISTINCT source FROM ubu WHERE kernel = 1 AND release = 'noble'")} == {"linux", "linux-aws", "linux-realtime"}
    assert conn.execute("SELECT COUNT(*) FROM ubu WHERE release = 'focal'").fetchone()[0] == n          # focal untouched
    assert "CVEs" in note and rows == conn.execute("SELECT COUNT(*) FROM ubu WHERE release = 'noble'").fetchone()[0]
    d = conn.execute("SELECT descr FROM ubu_cve WHERE cve = 'CVE-2006-10002'").fetchone()
    assert d["descr"].startswith("XML::Parser")
    # A file that does not parse keeps what was there.
    bad = tmp_path / "bad.bz2"
    bad.write_bytes(bz2.compress(b"<oval_definitions xmlns='http://oval.mitre.org/XMLSchema/oval-definitions-5'><definitions><definition class='vulnerab"))
    before = conn.execute("SELECT COUNT(*) FROM ubu WHERE release = 'noble'").fetchone()[0]
    with pytest.raises(Exception):
        feeds.load_ubuntu(conn, bad, feeds.ubuntu_feed("noble"), set())
    assert conn.execute("SELECT COUNT(*) FROM ubu WHERE release = 'noble'").fetchone()[0] == before


def test_the_cve_text_is_in_its_own_table_so_the_debian_loader_does_not_wipe_it(tmp_path):
    conn = loaded(tmp_path)
    from .test_cve import tracker_gz
    feeds.load_debian(conn, tracker_gz(tmp_path), {"trixie"})                 # replaces the whole `cve` table
    assert conn.execute("SELECT 1 FROM ubu_cve WHERE cve = 'CVE-2006-10002'").fetchone()
    ubuntu.match_host(conn, "h", ubuntu_inv([["libxml-parser-perl", "2.46-1", []]]), "g")
    assert match.host_cves(conn, "h")[0]["descr"].startswith("XML::Parser")


def test_a_cve_db_from_before_the_ubuntu_tables_still_reads(tmp_path):
    conn = store.connect(tmp_path / "old.db")
    conn.execute("DROP TABLE ubu_cve")
    conn.execute("INSERT INTO match VALUES ('h', 'a', 'CVE-2026-1', 'fix', '1', '2', NULL)")
    assert match.host_cves(conn, "h")[0]["cve"] == "CVE-2026-1"


# --- version order: Ubuntu's suffixes ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("a, b", [
    ("2.4.41-4ubuntu3.22", "2.4.41-4ubuntu3.23+esm2"), ("2.4.41-4ubuntu3.23", "2.4.41-4ubuntu3.23+esm1"), ("2.4.41-4ubuntu3.23+esm1", "2.4.41-4ubuntu3.23+esm2"),
    ("2.4.41-4ubuntu3.23+esm2", "2.4.41-4ubuntu3.24"),                          # +esm sorts after the plain version and before the next one
    ("1.2-4ubuntu0.20.04.1~esm4", "1.2-4ubuntu0.20.04.1~esm5"), ("1.2-4ubuntu0.20.04.1~esm5", "1.2-4ubuntu0.20.04.1"),      # ~esm sorts before the plain version
    ("1.2-4", "1.2-4ubuntu0.20.04.1~esm5"),
    ("5.2.21-2ubuntu4", "5.2.21-2ubuntu4.1"), ("5.2.21-2build1", "5.2.21-2ubuntu1"), ("5.2.21-2", "5.2.21-2build1"), ("5.2.21-2build1", "5.2.21-2build2"),
    ("2.9.14+dfsg-1.3ubuntu3", "2.9.14+dfsg-1.3ubuntu3.1"), ("3.8.10-0ubuntu1~20.04.17", "3.8.10-0ubuntu1~20.04.18+esm1"),
    ("1:9.18.1-1ubuntu1", "1:9.18.1-1ubuntu1.1"), ("2.38-1ubuntu6", "1:1.0-1"),    # an epoch beats everything
    ("6.8.0-31.31", "6.8.0-35.35"), ("6.8.0-9.9", "6.8.0-31.31"), ("6.8.0-1009.9", "6.8.0-1009.10"), ("6.11.0-17.17~24.04.2", "6.11.0-29.29~24.04.1"),
    ("7:6.1.1-3ubuntu5", "7:6.1.1-3ubuntu5+esm10")])
def test_ubuntu_versions_order_by_dpkg_rules(a, b):
    assert debver.compare(a, b) == -1 and debver.compare(b, a) == 1


VERSIONS = FIX / "ubuntu-versions.txt"


@pytest.mark.skipif(not shutil.which("dpkg"), reason="dpkg not installed")
def test_the_comparison_matches_dpkg_on_real_ubuntu_versions():
    """150 real fixed versions from the noble and focal files (ubuntu, build, +esm and ~esm among them), 600 seeded pairs. A run over
    all 6,149 distinct fixed versions of both files and 6,000 pairs found no difference from dpkg 1.22.22; see docs/DESIGN.md."""
    versions = [line.strip() for line in VERSIONS.read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert len(versions) > 100 and any("+esm" in v for v in versions) and any("~esm" in v for v in versions) and any("build" in v for v in versions)
    rng = random.Random(11)
    for a, b in [tuple(rng.sample(versions, 2)) for _ in range(600)]:
        op = {-1: "lt", 0: "eq", 1: "gt"}[debver.compare(a, b)]
        assert subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True).returncode == 0, f"{a} {op} {b}"


# --- the state of one CVE ----------------------------------------------------------------------------------------------------

FIXED = [("", "fixed", "2.47-1ubuntu0.24.04.1")]
ESM_APPS = [("esm-apps", "fixed", "1.2-4.1ubuntu2.24.0.4.1+esm3")]
ESM_INFRA = [("esm-infra", "fixed", "2.4.41-4ubuntu3.23+esm2")]
OPEN = [("", "open", None)]


@pytest.mark.parametrize("rows, installed, esm, priority, want", [
    (FIXED, "2.46-1", None, "medium", ("fix", "2.47-1ubuntu0.24.04.1")),
    (FIXED, "2.47-1ubuntu0.24.04.1", None, "medium", None),                    # fixed already
    (FIXED, "2.47-1ubuntu0.24.04.2", None, "medium", None),
    (FIXED, "2.46-1", None, "negligible", ("fix", "2.47-1ubuntu0.24.04.1")),  # negligible does not change the state; the vendor rule of cve/priority.py uses it
    (OPEN, "1.0", None, "medium", ("nofix", None)),
    (OPEN, "1.0", None, "negligible", ("nofix", None)),
    (OPEN, "1.0", None, "", ("nofix", None)),
    (ESM_APPS, "1.2-4.1ubuntu2.24.0.4.1+esm2", None, "low", ("esm", "1.2-4.1ubuntu2.24.0.4.1+esm3")),
    (ESM_APPS, "1.2-4.1ubuntu2.24.0.4.1+esm2", frozenset(), "low", ("esm", "1.2-4.1ubuntu2.24.0.4.1+esm3")),
    (ESM_APPS, "1.2-4.1ubuntu2.24.0.4.1+esm2", frozenset({"esm-infra"}), "low", ("esm", "1.2-4.1ubuntu2.24.0.4.1+esm3")),     # the wrong service
    (ESM_APPS, "1.2-4.1ubuntu2.24.0.4.1+esm2", frozenset({"esm-apps"}), "low", ("fix", "1.2-4.1ubuntu2.24.0.4.1+esm3")),
    (ESM_APPS, "1.2-4.1ubuntu2.24.0.4.1+esm3", frozenset({"esm-apps"}), "low", None),
    (ESM_INFRA, "2.4.41-4ubuntu3.22", frozenset({"esm-infra"}), "medium", ("fix", "2.4.41-4ubuntu3.23+esm2")),
    (ESM_INFRA, "2.4.41-4ubuntu3.22", frozenset({"esm-apps"}), "medium", ("esm", "2.4.41-4ubuntu3.23+esm2")),
    # A fix in the plain archive and a later one in ESM: the highest decides, and the host with no Pro cannot take it.
    ([("", "fixed", "2.4.41-4ubuntu3.22"), ("esm-infra", "fixed", "2.4.41-4ubuntu3.23+esm2")], "2.4.41-4ubuntu3.20", None, "medium", ("esm", "2.4.41-4ubuntu3.23+esm2")),
    ([("", "fixed", "2.4.41-4ubuntu3.22"), ("esm-infra", "fixed", "2.4.41-4ubuntu3.23+esm2")], "2.4.41-4ubuntu3.22", None, "medium", ("esm", "2.4.41-4ubuntu3.23+esm2")),
    ([("", "fixed", "2.4.41-4ubuntu3.22"), ("esm-infra", "fixed", "2.4.41-4ubuntu3.23+esm2")], "2.4.41-4ubuntu3.23", None, "medium", ("esm", "2.4.41-4ubuntu3.23+esm2")),
    ([("", "fixed", "2.4.41-4ubuntu3.22"), ("esm-infra", "fixed", "2.4.41-4ubuntu3.23+esm2")], "2.4.41-4ubuntu3.23+esm2", None, "medium", None),
    # ~esm sorts below the plain version, so the plain release version is already past a ~esm fix.
    ([("esm-apps", "fixed", "1.2-4ubuntu0.20.04.1~esm5")], "1.2-4ubuntu0.20.04.1", None, "low", None),
    ([("esm-apps", "fixed", "1.2-4ubuntu0.20.04.1~esm5")], "1.2-4", None, "low", ("esm", "1.2-4ubuntu0.20.04.1~esm5")),
    # Still open in one pocket after a fix in another: the open row remains once the fixed one no longer applies.
    ([("", "fixed", "1.0-1"), ("esm-apps", "open", None)], "1.0-2", None, "medium", ("nofix", None)),
    ([("", "fixed", "1.0-1")], "not a version!", None, "medium", None),
])
def test_classify(rows, installed, esm, priority, want):
    assert ubuntu.classify(rows, installed, esm, priority) == want


# --- matching a host ---------------------------------------------------------------------------------------------------------

NOBLE_HOST = [
    ["libxml-parser-perl", "2.46-1", ["libxml-parser-perl"]], ["libxml2", "2.9.14+dfsg-1.3ubuntu3", ["libxml2"]],
    ["openssl", "3.0.13-0ubuntu3.4", ["libssl3t64"]],                     # past the fix in the file
    ["krb5", "1.20.1-6ubuntu2.4", []],                                    # a fix exists, negligible
    ["nvidia-cg-toolkit", "3.1.0013-5", []], ["gcc-mingw-w64", "26ubuntu1", []],                          # open
    ["libxmltok", "1.2-4.1ubuntu2.24.0.4.1+esm2", []],                    # fixed in esm-apps; also open in esm-apps for another CVE
    ["bash", "5.2.21-2ubuntu4", []]]                                      # nothing about it in this file


def test_a_noble_host_gets_each_state(tmp_path):
    conn = loaded(tmp_path)
    out = ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST), "g")
    assert out["packages"] == 8
    got = rows_of(conn, "u1")
    assert got[("libxml-parser-perl", "CVE-2006-10002")] == ("fix", "2.46-1", "2.47-1ubuntu0.24.04.1", "medium")
    assert got[("libxml2", "CVE-2022-49043")] == ("fix", "2.9.14+dfsg-1.3ubuntu3", "2.9.14+dfsg-1.3ubuntu3.1", "medium")
    assert ("openssl", "CVE-2023-5363") not in got
    assert got[("krb5", "CVE-2024-26458")] == ("fix", "1.20.1-6ubuntu2.4", "1.20.1-6ubuntu2.5", "negligible")
    assert got[("nvidia-cg-toolkit", "CVE-2008-5144")] == ("nofix", "3.1.0013-5", None, "negligible")
    assert got[("gcc-mingw-w64", "CVE-2002-2439")] == ("nofix", "26ubuntu1", None, "low")
    assert got[("libxmltok", "CVE-2012-1148")][:3] == ("esm", "1.2-4.1ubuntu2.24.0.4.1+esm2", "1.2-4.1ubuntu2.24.0.4.1+esm3")     # no Pro: not available
    assert got[("libxmltok", "CVE-2025-66382")][0] == "nofix" and not [k for k in got if k[0] == "bash"]
    m = conn.execute("SELECT * FROM matched WHERE host = 'u1'").fetchone()
    assert m["packages"] == 8 and m["gen"] == "g" and "Ubuntu Pro is not known" in m["note"]
    # The same host reporting Pro (esm-apps on) takes the ESM fix as an ordinary one; reporting Pro off says nothing is unknown.
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST, esm=["apps"]), "g")
    assert rows_of(conn, "u1")[("libxmltok", "CVE-2012-1148")][0] == "fix" and not conn.execute("SELECT note FROM matched").fetchone()["note"]
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST, esm=[]), "g")
    assert rows_of(conn, "u1")[("libxmltok", "CVE-2012-1148")][0] == "esm" and not conn.execute("SELECT note FROM matched").fetchone()["note"]
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST, esm=["infra"]), "g")                          # infra does not cover an esm-apps fix
    assert rows_of(conn, "u1")[("libxmltok", "CVE-2012-1148")][0] == "esm"


def test_a_focal_host_with_esm_infra_off_and_on(tmp_path):
    conn = loaded(tmp_path)
    src = [["apache2", "2.4.41-4ubuntu3.20", ["apache2-bin"]], ["systemd", "245.4-4ubuntu3.24+esm1", []], ["libxml2", "2.9.10+dfsg-5ubuntu0.20.04.3", []]]
    ubuntu.match_host(conn, "f1", ubuntu_inv(src, "focal", "20.04", esm=[]), "g")
    got = rows_of(conn, "f1")
    assert got[("apache2", "CVE-2024-42516")][:3] == ("esm", "2.4.41-4ubuntu3.20", "2.4.41-4ubuntu3.23+esm2")
    assert got[("apache2", "CVE-2019-17567")][0] == "nofix" and not [k for k in got if k[0] == "systemd"]       # at the ESM fix: fixed
    assert got[("libxml2", "CVE-2016-3709")][0] == "fix"                                                          # the plain archive, not ESM
    ubuntu.match_host(conn, "f1", ubuntu_inv(src, "focal", "20.04", esm=["infra"]), "g")
    assert rows_of(conn, "f1")[("apache2", "CVE-2024-42516")][0] == "fix"


def test_a_kernel_counts_only_with_its_image_and_only_for_the_flavors_loaded(tmp_path):
    conn = loaded(tmp_path)
    run_k = ["linux-image-6.8.0-31-generic"]
    ubuntu.match_host(conn, "k1", ubuntu_inv([["linux", "6.8.0-31.31", run_k], ["linux-aws", "6.8.0-1005.5", ["linux-image-6.8.0-1005-aws"]]]), "g")
    got = rows_of(conn, "k1")
    assert got[("linux", "CVE-2020-12351")] == ("fix", "6.8.0-31.31", "6.8.0-35.35", "high")
    assert got[("linux", "CVE-2022-49034")][2] == "6.8.0-58.60" and got[("linux-aws", "CVE-2020-12351")][2] == "6.8.0-1009.9"
    # Headers and tools built from the kernel's source (linux-libc-dev in a container) do not run it.
    ubuntu.match_host(conn, "k2", ubuntu_inv([["linux", "6.8.0-31.31", ["linux-libc-dev"]], ["linux-realtime", "6.8.0-31.31", []]]), "g")
    assert rows_of(conn, "k2") == {}
    # A running kernel that is already past the fix.
    ubuntu.match_host(conn, "k3", ubuntu_inv([["linux", "6.8.0-58.60", run_k]]), "g")
    assert [k for k in rows_of(conn, "k3") if k[1] == "CVE-2020-12351"] == [] and [k for k in rows_of(conn, "k3") if k[1] == "CVE-2022-49034"] == []
    # A flavor that was not loaded has no rows: its CVEs are not known here (the chore loads the flavors the hub's hosts run).
    ubuntu.match_host(conn, "k4", ubuntu_inv([["linux-azure", "6.8.0-1005.5", ["linux-image-6.8.0-1005-azure"]]]), "g")
    assert rows_of(conn, "k4") == {}


def test_a_release_with_no_data_and_a_host_that_is_not_ubuntu_say_so_and_match_nothing(tmp_path):
    conn = loaded(tmp_path)
    out = ubuntu.match_host(conn, "j1", ubuntu_inv([["bash", "1", []]], "jammy", "22.04"), "g")
    assert out["cves"] == 0 and "Ubuntu 22.04: no CVE data downloaded for this release" in out["note"]
    out = ubuntu.match_host(conn, "m1", {**ubuntu_inv([["bash", "1", []]]), "os_id": "linuxmint", "codename": "wilma"}, "g")
    assert out["cves"] == 0 and "covers Debian, Raspberry Pi OS and Ubuntu" in out["note"]
    assert conn.execute("SELECT COUNT(*) FROM match WHERE host IN ('j1', 'm1')").fetchone()[0] == 0
    # Rematching replaces, not adds.
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST), "g")
    n = conn.execute("SELECT COUNT(*) FROM match WHERE host = 'u1'").fetchone()[0]
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST), "g")
    assert conn.execute("SELECT COUNT(*) FROM match WHERE host = 'u1'").fetchone()[0] == n > 5


EXPOSURE = exposure.Exposure(False, "test")


# --- findings for a host -----------------------------------------------------------------------------------------------------

def findings_for(conn, host, **kw):
    return {f.key: f for f in match.package_findings(match.host_cves(conn, host, ("fix", "esm", "nofix")), {}, set(), EXPOSURE, 0.04, "apt", False, "ubuntu")}


def test_findings_say_ubuntu_name_the_priority_and_do_not_count_an_esm_fix_as_an_ordinary_update(tmp_path):
    conn = loaded(tmp_path)
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST), "g")
    f = findings_for(conn, "u1")
    assert set(f) == {"libxml-parser-perl", "libxml2", "libxmltok", "krb5"}         # open rows with no KEV entry raise nothing
    p = f["libxml-parser-perl"]
    # Not exposed, not in KEV, no EPSS score (so not automatable) and an estimated partial impact: Table 1 row 16, fix at the upgrade.
    assert p.severity == "low" and p.title == "libxml-parser-perl: CVE-2006-10002 is fixed in an update; fix at the next upgrade"
    k = f["krb5"]                                                    # the same, and Ubuntu calls it negligible: the vendor rule says so
    assert k.severity == "low" and "lowered by the vendor's rating" in k.howto and "Ubuntu priority negligible" in k.detail
    assert "fixed in 2.47-1ubuntu0.24.04.1" in p.detail and "Ubuntu priority medium" in p.detail and "Debian" not in p.detail
    assert p.fix.startswith("sudo apt") and "pro " not in p.fix
    e = f["libxmltok"]
    assert "Ubuntu Pro" in e.title
    assert "only in Ubuntu Pro's ESM archives" in e.detail and "apt does not install it" in e.detail
    assert "pro security-status" in e.fix and "pro enable esm-infra esm-apps" in e.fix and e.fix.endswith("sudo apt upgrade")
    # With Pro on for esm-apps the same CVE is an ordinary update, with apt's command, and the text no longer warns.
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST, esm=["apps"]), "g")
    e = findings_for(conn, "u1")["libxmltok"]
    assert "fixed in an update" in e.title and e.fix.startswith("sudo apt") and "pro enable" not in e.fix


def test_a_known_exploited_cve_makes_a_high_finding_and_an_unfixed_one_says_ubuntu_has_no_fix(tmp_path):
    conn = loaded(tmp_path)
    conn.execute("INSERT INTO kev VALUES ('CVE-2022-49043', 'x', 'libxml2', 'libxml2 test', '2026-01-01', 'Unknown')")
    conn.execute("INSERT INTO kev VALUES ('CVE-2002-2439', 'gnu', 'gcc', 'gcc test', '2026-01-01', 'Unknown')")
    conn.execute("INSERT INTO epss VALUES ('CVE-2006-10002', 0.5, 0.97)")
    ubuntu.match_host(conn, "u1", ubuntu_inv(NOBLE_HOST), "g")
    f = findings_for(conn, "u1")
    assert f["libxml2"].severity == "high" and "CISA KEV" in f["libxml2"].title
    # EPSS 0.5 is at or above the 0.04 default: automatable (estimated). Not exposed, not KEV, partial: row 14, 60 days.
    assert f["libxml-parser-perl"].severity == "medium" and f["libxml-parser-perl"].title.endswith("fix within 60 days")
    assert "EPSS 50.0% (97th)" in f["libxml-parser-perl"].detail and f["libxml2"].title.endswith("fix within 14 days")
    g = f["gcc-mingw-w64"]                                        # an exploited CVE with no fix: still raised, and the text is Ubuntu's
    assert g.severity == "high" and "Ubuntu has no fix yet" in g.detail and "https://ubuntu.com/security/CVE-2002-2439" in g.detail and "Debian" not in g.detail


def test_the_kernel_finding_names_the_flavor_and_asks_for_a_reboot(tmp_path):
    conn = loaded(tmp_path)
    src = [["linux-aws", "6.8.0-1005.5", ["linux-image-6.8.0-1005-aws"]]]
    ubuntu.match_host(conn, "k1", ubuntu_inv(src), "g")
    f = {f.key: f for f in match.package_findings(match.host_cves(conn, "k1", ("fix", "esm", "nofix")), {"linux-aws": ["linux-image-6.8.0-1005-aws"]},
                                                  set(), EXPOSURE, 0.04, "apt", False, "ubuntu")}["linux-aws"]
    assert "Running kernel 6.8.0-1005.5" in f.detail and f.fix.endswith("sudo reboot")
    g = {f.key: f for f in match.package_findings(match.host_cves(conn, "k1", ("fix", "esm", "nofix")), {"linux-aws": ["linux-image-6.8.0-1005-aws"]},
                                                  set(), EXPOSURE, 0.04, "apt", True, "ubuntu")}["linux-aws"]
    assert g.fix == "sudo reboot" and "A newer kernel is installed" in g.detail


# --- the download ------------------------------------------------------------------------------------------------------------

def chore(tmp_path, client):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    return cfg, run.Chore(cfg, None, client)


def feed_rows(cfg):
    conn = store.connect(cfg.cve_db_path)
    try:
        return {r["name"]: dict(r) for r in conn.execute("SELECT * FROM feed WHERE name LIKE 'ubuntu-%'")}
    finally:
        conn.close()


def ubu_count(cfg, release="noble"):
    conn = store.connect(cfg.cve_db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM ubu WHERE release = ?", (release,)).fetchone()[0]
    finally:
        conn.close()


def refresh(c, kernels, now):
    async def go():
        conn = c.factory()
        try:
            return await c._refresh_ubuntu(conn, kernels, now)
        finally:
            conn.close()
    return asyncio.run(go())


def test_each_release_asks_one_file_once_a_day_with_a_conditional_get(tmp_path):
    calls = []
    cfg, c = chore(tmp_path, serve(tmp_path, calls))
    now = 1_800_000_000.0
    assert refresh(c, {"noble": {"linux"}}, now) is True
    canon = [(h, d) for h, d in calls if h == ubuntu.OVAL_HOST]
    assert len(canon) == 1 and "if-none-match" not in canon[0][1]
    rows = feed_rows(cfg)
    assert set(rows) == {"ubuntu-noble"} and rows["ubuntu-noble"]["status"] == "ok" and rows["ubuntu-noble"]["etag"] == '"v1"'
    assert rows["ubuntu-noble"]["url"] == "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2"
    assert rows["ubuntu-noble"]["last_modified"] and rows["ubuntu-noble"]["rows"] == ubu_count(cfg) > 10 and "CVEs" in rows["ubuntu-noble"]["note"]
    assert (Path(cfg.data_dir) / "cve" / "ubuntu-noble.oval.xml.bz2").read_bytes()[:3] == b"BZh"
    # An hour later nothing is asked; a day later the file is asked with its validators and answers 304.
    assert refresh(c, {"noble": {"linux"}}, now + 3600) is False and len(calls) == 1
    assert refresh(c, {"noble": {"linux"}}, now + DAY + 5) is False
    assert calls[1][1]["if-none-match"] == '"v1"' and calls[1][1]["if-modified-since"].startswith("Thu, 19 Nov")
    assert feed_rows(cfg)["ubuntu-noble"]["status"] == "not modified" and ubu_count(cfg) > 10
    # Only a generic User-Agent goes out (serve asserts the DaemonSight/<version> form), and no cookie or token.
    assert all(set(d) <= {"host", "accept", "accept-encoding", "connection", "user-agent", "if-none-match", "if-modified-since"} for _h, d in calls)


def test_a_failed_download_keeps_the_last_good_copy_and_says_so(tmp_path):
    cfg, c = chore(tmp_path, serve(tmp_path))
    now = 1_800_000_000.0
    refresh(c, {"noble": {"linux"}}, now)
    before = ubu_count(cfg)
    c.client = serve(tmp_path, override={ubuntu.OVAL_HOST: lambda r: httpx.Response(503)})
    assert refresh(c, {"noble": {"linux"}}, now + DAY + 5) is False
    row = feed_rows(cfg)["ubuntu-noble"]
    assert row["status"] == "error" and row["detail"] == "HTTP 503" and row["ok_at"] == now and ubu_count(cfg) == before
    # An error is tried again after an hour, not a day.
    calls = []
    c.client = serve(tmp_path, calls, override={ubuntu.OVAL_HOST: lambda r: httpx.Response(503)})
    refresh(c, {"noble": {"linux"}}, now + DAY + 5 + 1800)
    assert calls == []
    refresh(c, {"noble": {"linux"}}, now + DAY + 5 + 3600)
    assert len(calls) == 1
    # A file that downloads but is not bzip2, and one that is bzip2 but not OVAL, each keep the rows.
    c.client = serve(tmp_path, override={ubuntu.OVAL_HOST: lambda r: httpx.Response(200, content=b"<html>not it</html>", headers={"etag": '"v2"'})})
    refresh(c, {"noble": {"linux"}}, now + 3 * DAY)
    row = feed_rows(cfg)["ubuntu-noble"]
    assert row["status"] == "error" and "bzip2" in row["detail"] and ubu_count(cfg) == before
    c.client = serve(tmp_path, override={ubuntu.OVAL_HOST: lambda r: httpx.Response(200, content=bz2.compress(b"<html/>"), headers={"etag": '"v2"'})})
    refresh(c, {"noble": {"linux"}}, now + 4 * DAY)
    row = feed_rows(cfg)["ubuntu-noble"]
    assert row["status"] == "error" and "OvalError" in row["detail"] and row["etag"] is None and ubu_count(cfg) == before
    c.client = serve(tmp_path)
    refresh(c, {"noble": {"linux"}}, now + 5 * DAY)
    assert feed_rows(cfg)["ubuntu-noble"]["status"] == "ok" and ubu_count(cfg) == before


def test_a_release_canonical_has_no_file_for_is_an_answer_not_an_error(tmp_path):
    cfg, c = chore(tmp_path, serve(tmp_path))
    now = 1_800_000_000.0
    assert refresh(c, {"noble": {"linux"}, "jammy": set()}, now) is True
    row = feed_rows(cfg)["ubuntu-jammy"]
    assert row["status"] == "absent" and row["ok_at"] == now and row["detail"] is None and row["rows"] == 0 and "not in Canonical's OVAL data" in row["note"]
    assert ubu_count(cfg, "jammy") == 0 and not (Path(cfg.data_dir) / "cve" / "ubuntu-jammy.oval.xml.bz2").exists()
    conn = store.connect(cfg.cve_db_path)
    assert feeds.stale_feeds(conn, now + 2 * DAY) == []
    conn.close()
    assert refresh(c, {"noble": {"linux"}, "jammy": set()}, now + DAY + 5) is False and feed_rows(cfg)["ubuntu-jammy"]["status"] == "absent"


def test_a_release_nothing_runs_any_more_is_forgotten_and_a_new_kernel_flavor_reads_the_saved_file_again(tmp_path):
    calls = []
    cfg, c = chore(tmp_path, serve(tmp_path, calls))
    now = 1_800_000_000.0
    refresh(c, {"noble": {"linux"}, "focal": set()}, now)
    assert ubu_count(cfg, "focal") > 0 and len(calls) == 2
    # A host on another flavor reports: the saved file is parsed again, with no download.
    assert refresh(c, {"noble": {"linux", "linux-aws"}, "focal": set()}, now + 60) is True and len(calls) == 2
    conn = store.connect(cfg.cve_db_path)
    assert {r[0] for r in conn.execute("SELECT DISTINCT source FROM ubu WHERE release = 'noble' AND kernel = 1")} == {"linux", "linux-aws"}
    conn.close()
    assert refresh(c, {"noble": {"linux", "linux-aws"}, "focal": set()}, now + 120) is False                  # the same set: nothing
    assert refresh(c, {"noble": {"linux", "linux-aws"}}, now + 180) is True
    assert ubu_count(cfg, "focal") == 0 and set(feed_rows(cfg)) == {"ubuntu-noble"} and not (Path(cfg.data_dir) / "cve" / "ubuntu-focal.oval.xml.bz2").exists()
    assert refresh(c, {}, now + 240) is True and feed_rows(cfg) == {} and ubu_count(cfg) == 0


def test_a_redirect_off_canonicals_host_a_huge_file_and_a_wrong_start_are_refused(tmp_path):
    async def go():
        conn = store.connect(tmp_path / "c.db")
        f = feeds.ubuntu_feed("noble")
        row = feeds.feed_row(conn, f)

        def hop(request):
            if request.url.host == ubuntu.OVAL_HOST:
                return httpx.Response(302, headers={"location": "https://evil.example/noble.bz2"})
            return httpx.Response(200, content=b"BZh")
        with pytest.raises(feeds.FetchError, match="not a source"):
            await feeds.download(f, row, tmp_path / "a.bz2", httpx.AsyncClient(transport=httpx.MockTransport(hop), follow_redirects=True))
        big = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"BZh" + b"0" * feeds.UBUNTU_MAX_BYTES)))
        with pytest.raises(feeds.FetchError, match="larger"):
            await feeds.download(f, row, tmp_path / "b.bz2", big)
        gz = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"\x1f\x8b0000")))
        with pytest.raises(feeds.FetchError, match="bzip2"):
            await feeds.download(f, row, tmp_path / "c.bz2", gz)
        assert not any((tmp_path / n).exists() for n in ("a.bz2", "b.bz2", "c.bz2"))
        assert f.max_bytes == 80 << 20
    asyncio.run(go())


# --- the chore, end to end, for a host ---------------------------------------------------------------------------------------

def put_ubuntu(conn, host, sources, taken_at=None, **kw):
    data = {k: v for k, v in ubuntu_inv(sources, **kw).items() if k != "taken_at"}
    db.put_snapshot(conn, host, "inventory", taken_at or time.time(), True, None, {**data, "v": 1})


def test_the_chore_matches_an_ubuntu_host_and_its_findings_fire_and_clear(tmp_path):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    state = db.connect_writer(cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('u1', 'x', 0)")
    sources = [["libxml-parser-perl", "2.46-1", []], ["libxmltok", "1.2-4.1ubuntu2.24.0.4.1+esm2", []], ["bash", "5.2.21-2ubuntu4", []],
               ["linux", "6.8.0-31.31", ["linux-image-6.8.0-31-generic"]]]
    now = time.time()
    put_ubuntu(state, "u1", sources, taken_at=now)
    calls = []

    async def go():
        ch = run.Chore(cfg, state, serve(tmp_path, calls))
        await ch.run_once(now)
        open_ = {(r["rule"], r["key"]): r for r in db.open_findings(state, "u1")}
        assert {k for k in open_ if k[0] == "cve.package"} == {("cve.package", "libxml-parser-perl"), ("cve.package", "libxmltok"), ("cve.package", "linux")}
        assert open_[("cve.package", "libxml-parser-perl")]["severity"] == "low" and "Ubuntu Pro" in open_[("cve.package", "libxmltok")]["title"]
        assert len([1 for h, _d in calls if h == ubuntu.OVAL_HOST]) == 1                      # the one release this host runs
        cdb = store.connect(cfg.cve_db_path)
        assert {r[0] for r in cdb.execute("SELECT DISTINCT source FROM ubu WHERE kernel = 1")} == {"linux"}      # the flavor this host runs
        assert cdb.execute("SELECT COUNT(*) FROM deb").fetchone()[0] == 0                       # no Debian release is needed, so none is loaded
        assert cdb.execute("SELECT note FROM matched WHERE host = 'u1'").fetchone()["note"]     # Pro is not known
        # The host turns on esm-apps: the ESM fix becomes an ordinary update (a new inventory, matched again).
        put_ubuntu(state, "u1", sources, taken_at=now + 100, esm=["apps"], h="b2")
        await ch.run_once(now + 200)
        open_ = {(r["rule"], r["key"]): r for r in db.open_findings(state, "u1")}
        assert "fixed in an update" in open_[("cve.package", "libxmltok")]["title"]
        # The host takes the updates: the findings clear.
        put_ubuntu(state, "u1", [["libxml-parser-perl", "2.47-1ubuntu0.24.04.1", []], ["libxmltok", "1.2-4.1ubuntu2.24.0.4.1+esm3", []], ["bash", "5.2.21-2ubuntu4", []],
                                 ["linux", "6.8.0-99.99", ["linux-image-6.8.0-99-generic"]]], taken_at=now + 300, esm=["apps"], h="c3")
        await ch.run_once(now + 400)
        left = {k for k in ((r["rule"], r["key"]) for r in db.open_findings(state, "u1")) if k[0] == "cve.package"}
        assert left == set()                                                                    # the open CVEs have no known exploit: listed on the page, no finding
        # The OVAL file stops answering for three days: a low cve.feed_stale finding names it.
        ch.client = serve(tmp_path, override={h: (lambda r: httpx.Response(503)) for h in (ubuntu.OVAL_HOST, "security-tracker.debian.org", "epss.empiricalsecurity.com", "www.cisa.gov")})
        await ch.run_once(now + 5 * DAY)
        stale = [r for r in db.open_findings(state, "u1") if r["rule"] == "cve.feed_stale"]
        assert len(stale) == 1 and "Ubuntu CVE data (noble)" in stale[0]["detail"]
        cdb.close()
    asyncio.run(go())
    state.close()


# --- the page ----------------------------------------------------------------------------------------------------------------

def seed_ubuntu_hub(hub_cfg, token, tmp_path, esm=None):
    from .test_cve import page_client
    from .test_hub import body, post
    c = page_client(hub_cfg, token)
    inv_ = ubuntu_inv(NOBLE_HOST, esm=esm)
    inv_.update({"v": 1, "taken_at": time.time()})
    assert post(c, body(inventory=inv_), token).status_code == 200
    cdb = store.connect(hub_cfg.cve_db_path)
    for rel in ("noble",):
        f = feeds.ubuntu_feed(rel)
        feeds.load_ubuntu(cdb, oval_bz2(tmp_path, rel), f, {"linux"})
        feeds.feed_row(cdb, f)
        feeds._record(cdb, f, checked_at=time.time(), ok_at=time.time(), changed_at=time.time(), status="ok", rows=30, size=40_000_000)
    from .test_cve import epss_gz, kev_gz
    feeds.load_epss(cdb, epss_gz(tmp_path))
    feeds.load_kev(cdb, kev_gz(tmp_path))
    conn = db.connect_writer(hub_cfg.db_path)
    snap = db.get_snapshot(conn, "testhost", "inventory")
    ubuntu.match_host(cdb, "testhost", {**snap.data, "taken_at": snap.taken_at}, "g")
    cdb.close()
    return c


def test_the_vulnerabilities_page_for_an_ubuntu_host(hub_cfg, token, tmp_path, seeded):
    from .test_provenance import check_panels
    c = seed_ubuntu_hub(hub_cfg, token, tmp_path)
    html = c.get("/h/testhost/vulnerabilities").text
    assert "phase 3b" not in html and "Ubuntu is planned" not in html
    assert "Fix needs Ubuntu Pro" in html and "fixed only in the ESM archives" in html and "Ubuntu marks them as not needing a fix" in html
    assert 'id="cve-libxml-parser-perl"' in html and "https://ubuntu.com/security/CVE-2006-10002" in html and "security-tracker.debian.org/tracker/CVE-" not in html
    assert "needs Pro" in html and "priority medium" in html and ">Priority<" in html and "Ubuntu Pro ESM on this host: not known: this collector does not report it" in html
    assert "Ubuntu CVE data (noble)" in html and "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2" in html
    assert "CC BY-SA 4.0" in html or "Attribution-ShareAlike 4.0" in html
    # The (i) panels: the commands to check the same thing by hand.
    assert "pro security-status" in html and "apt list --upgradable" in html and "pro fix CVE-2024-6387 --dry-run" in html
    assert "ubuntu-esm-infra" in html and "bzcat" in html and check_panels(html) >= 3
    for row in re.findall(r"<tr data-row.*?</tr>", html, re.S):
        assert all("data-label=" in t for t in re.findall(r"<td[^>]*>", row))
    assert c.get("/h/testhost/partials/vulnerabilities").status_code == 200


def test_the_page_says_what_pro_services_the_host_has(hub_cfg, token, tmp_path, seeded):
    c = seed_ubuntu_hub(hub_cfg, token, tmp_path, esm=["apps"])
    html = c.get("/h/testhost/vulnerabilities").text
    assert "Ubuntu Pro ESM on this host: on for esm-apps" in html
    c = seed_ubuntu_hub(hub_cfg, token, tmp_path, esm=[])
    assert "Ubuntu Pro ESM on this host: not on" in c.get("/h/testhost/vulnerabilities").text


# --- the collector -----------------------------------------------------------------------------------------------------------

UBUNTU_DPKG = (
    "ii \tlinux-signed\t6.8.0-31.31\tlinux-image-6.8.0-31-generic\t6.8.0-31.31\n"                  # the running signed image
    "ii \tlinux-signed\t6.8.0-35.35\tlinux-image-6.8.0-35-generic\t6.8.0-35.35\n"                  # another installed kernel
    "ii \tlinux\t6.8.0-31.31\tlinux-headers-6.8.0-31-generic\t6.8.0-31.31\n"
    "ii \tlinux\t6.8.0-31.31\tlinux-modules-6.8.0-31-generic\t6.8.0-31.31\n"
    "ii \tlinux\t6.8.0-35.35\tlinux-modules-6.8.0-35-generic\t6.8.0-35.35\n"
    "ii \tlinux\t6.8.0-35.35\tlinux-libc-dev\t6.8.0-35.35\n"
    "ii \tlinux-aws\t6.8.0-1005.5\tlinux-image-6.8.0-1005-aws\t6.8.0-1005.5\n"                      # an unsigned flavor, not running
    "ii \tlinux-aws\t6.8.0-1009.9\tlinux-image-6.8.0-1009-aws\t6.8.0-1009.9\n"
    "ii \tlinux-signed-hwe-6.8\t6.8.0-31.31~22.04.1\tlinux-image-6.8.0-31-generic\t6.8.0-31.31~22.04.1\n"
    "ii \tlinux-meta\t6.8.0.31.31\tlinux-image-generic\t6.8.0.31.31\n"
    "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n")


def test_an_ubuntu_inventory_lists_the_running_kernel_under_the_unsigned_source_name():
    rows = inv.parse_dpkg_query(UBUNTU_DPKG, "6.8.0-31-generic", ubuntu=True)
    names = {(r[0], r[1]): r[2] for r in rows}
    assert ("linux", "6.8.0-31.31") in names and "linux-image-6.8.0-31-generic" in names[("linux", "6.8.0-31.31")]
    assert ("linux-hwe-6.8", "6.8.0-31.31~22.04.1") in names                                         # linux-signed-hwe-6.8 is linux-hwe-6.8
    assert ("linux-signed", "6.8.0-31.31") not in names and ("linux-signed-hwe-6.8", "6.8.0-31.31~22.04.1") not in names
    # Not running: the other signed image, the other aws image's group, and the metapackage with an image.
    assert ("linux", "6.8.0-35.35") in names and "linux-image-6.8.0-35-generic" not in names[("linux", "6.8.0-35.35")]       # its modules and headers stay: no image, so the hub skips it
    assert not [k for k in names if k[0] == "linux-aws"] and not [k for k in names if k[0] == "linux-meta"]
    assert ("bash", "5.2.21-2ubuntu4") in names
    # Debian's behavior is the old one: linux-signed becomes `linux`, whatever the flavor.
    deb = inv.parse_dpkg_query(UBUNTU_DPKG, "6.8.0-31-generic")
    assert ("linux", "6.8.0-31.31~22.04.1") in {(r[0], r[1]) for r in deb} and ("linux-aws", "6.8.0-1005.5") in {(r[0], r[1]) for r in deb}


def test_the_ubuntu_inventory_carries_the_pro_services_and_its_hash_follows_them():
    osr = {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"}
    a = inv.inventory_apt(UBUNTU_DPKG, osr, "6.8.0-31-generic", [])
    b = inv.inventory_apt(UBUNTU_DPKG, osr, "6.8.0-31-generic", ["infra"])
    c = inv.inventory_apt(UBUNTU_DPKG, osr, "6.8.0-31-generic", None)
    assert a["esm"] == [] and b["esm"] == ["infra"] and "esm" not in c and len({a["hash"], b["hash"], c["hash"]}) == 3
    assert a["os_id"] == "ubuntu" and a["codename"] == "noble"
    deb = inv.inventory_apt("ii \tbash\t5.2-1\tbash\t5.2-1\n", {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"}, "6.12.0", ["apps"])
    assert "esm" not in deb                                                                             # only Ubuntu has Pro
    assert deb["hash"] == inv.inventory_apt("ii \tbash\t5.2-1\tbash\t5.2-1\n", {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"}, "6.12.0")["hash"]


def test_the_pro_services_come_from_the_apt_source_files_the_pro_client_writes():
    def fake(files):
        return lambda pattern: [pattern] if pattern in files else []
    assert inv.esm_services(fake(set())) == []
    assert inv.esm_services(fake({"/etc/apt/sources.list.d/ubuntu-esm-infra.sources"})) == ["infra"]
    assert inv.esm_services(fake({"/etc/apt/sources.list.d/ubuntu-esm-apps.list", "/etc/apt/sources.list.d/ubuntu-esm-infra.list"})) == ["infra", "apps"]


def test_the_hub_keeps_the_pro_services_of_an_inventory_and_ignores_a_bad_value():
    from daemonsight import hub
    ok = hub.InventoryIn.model_validate({"v": 1, "taken_at": 1.0, "backend": "apt", "os_id": "ubuntu", "esm": ["infra", "apps"]})
    assert ok.esm == ["infra", "apps"] and hub.InventoryIn.model_validate({"v": 1, "taken_at": 1.0, "backend": "apt"}).esm is None
    assert '"esm":[]' in hub.InventoryIn.model_validate({"v": 1, "taken_at": 1.0, "backend": "apt", "esm": []}).model_dump_json(exclude_defaults=True)
    with pytest.raises(Exception):
        hub.InventoryIn.model_validate({"v": 1, "taken_at": 1.0, "backend": "apt", "esm": ["../x"]})
