"""The urgency model (cve/priority.py): CISA BOD 26-04's Table 1 as a data file, the rating of one CVE, the estimates where CISA has
not rated it, the vendor rule, and loading, validating and overriding the table file."""

import copy
import json
import logging
from pathlib import Path

import pytest

from daemonsight.cve import match, priority

# Table 1 as published (https://www.cisa.gov/sites/default/files/styles/large/public/2026-06/BOD_26-04_Table_1_Remediation_Timelines_0.png),
# written out independently of the data file: (exposed, KEV, automatable, impact) -> (days or None for "fix on system upgrade", triage).
TABLE_1 = {
    1: ("Y", "Y", "Y", "total", 3, True), 2: ("Y", "Y", "Y", "partial", 3, False),
    3: ("Y", "Y", "N", "total", 3, True), 4: ("Y", "Y", "N", "partial", 14, False),
    5: ("Y", "N", "Y", "total", 3, False), 6: ("Y", "N", "Y", "partial", 14, False),
    7: ("Y", "N", "N", "total", 14, False), 8: ("Y", "N", "N", "partial", 60, False),
    9: ("N", "Y", "Y", "total", 3, True), 10: ("N", "Y", "Y", "partial", 14, False),
    11: ("N", "Y", "N", "total", 14, False), 12: ("N", "Y", "N", "partial", 14, False),
    13: ("N", "N", "Y", "total", 60, False), 14: ("N", "N", "Y", "partial", 60, False),
    15: ("N", "N", "N", "total", None, False), 16: ("N", "N", "N", "partial", None, False),
}
SEVERITY = {3: "critical", 14: "high", 60: "medium", None: "low"}
BUNDLED = Path(priority.__file__).resolve().parent.parent / "data" / "priority" / "bod-26-04.json"


def cve(kev, auto, impact, **kw):
    return {"kev": kev, "epss": 0.0, "automatable": "yes" if auto else "no", "impact": impact, **kw}


@pytest.mark.parametrize("n", sorted(TABLE_1))
def test_every_row_of_table_1(n):
    e, k, a, i, days, triage = TABLE_1[n]
    r = priority.rate(cve(k == "Y", a == "Y", i), e == "Y", 0.04)
    assert (r.row, r.days, r.triage, r.severity) == (n, days, triage, SEVERITY[days])
    assert (r.exposed, r.kev, r.automatable, r.impact) == (e == "Y", k == "Y", a == "Y", i)
    assert not r.estimated and not r.vendor_lowered and r.directive == "CISA BOD 26-04"
    assert r.deadline == ("Fix at the next upgrade" if days is None else f"Fix within {days} days (CISA BOD 26-04 timeline)")


def test_the_severity_follows_the_timeline():
    assert {d: priority.rate(cve(True, True, "total"), True, 0.04).severity for d in (3,)} == {3: "critical"}
    sev = {}
    for e, k, a, i, days, _t in TABLE_1.values():
        sev[days] = priority.rate(cve(k == "Y", a == "Y", i), e == "Y", 0.04).severity
    assert sev == {3: "critical", 14: "high", 60: "medium", None: "low"}


def test_the_rows_with_triage_name_it_in_the_text():
    r = priority.rate(cve(True, True, "total"), True, 0.04)
    assert r.triage and priority.basis_text(r) == "CISA BOD 26-04 Table 1 row 1: 3 days and forensic triage"
    r = priority.rate(cve(False, False, "partial"), False, 0.04)
    assert priority.basis_text(r) == "CISA BOD 26-04 Table 1 row 16: fix on system upgrade"


# --- the estimates ---------------------------------------------------------------------------------------------------------------

def test_without_a_cisa_rating_automatable_comes_from_epss_and_impact_is_partial_and_both_are_labelled():
    c = {"kev": False, "epss": 0.05, "automatable": None, "impact": None}
    r = priority.rate(c, True, 0.04)
    assert (r.automatable, r.impact, r.auto_estimated, r.impact_estimated, r.row, r.days) == (True, "partial", True, True, 6, 14)
    assert priority.rate({**c, "epss": 0.0399}, True, 0.04).automatable is False         # just under the threshold
    assert priority.rate({**c, "epss": 0.04}, True, 0.04).automatable is True            # at it
    assert priority.rate({**c, "epss": None}, True, 0.04).automatable is False           # no EPSS score
    assert priority.rate({**c, "epss": 0.05}, True, 0.1).automatable is False            # the setting moves it
    lines = priority.inputs_text(r, "port 443 is forwarded")
    assert lines[0] == "Publicly exposed: yes: port 443 is forwarded" and lines[1] == "In CISA's KEV catalog: no"
    assert lines[2] == "Automatable by an adversary: yes (estimated by DaemonSight, from the EPSS probability)"
    assert lines[3] == "Technical impact: partial (estimated by DaemonSight: CISA has not rated this CVE)"


def test_a_cisa_rating_is_used_as_it_is_and_one_field_can_be_missing():
    r = priority.rate({"kev": False, "epss": 0.9, "automatable": "no", "impact": "total"}, False, 0.04)
    assert (r.automatable, r.impact, r.estimated, r.row) == (False, "total", False, 15)      # EPSS is not consulted
    lines = priority.inputs_text(r)
    assert lines[2].endswith("(CISA)") and lines[3].endswith("(CISA)") and "estimated" not in "".join(lines)
    half = priority.rate({"kev": False, "epss": 0.9, "automatable": "yes", "impact": None}, False, 0.04)
    assert (half.auto_estimated, half.impact_estimated, half.estimated) == (False, True, True)


# --- the vendor rule -------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("urgency,exposed,kev,lowered", [
    ("unimportant", False, False, True),        # Debian, not exposed, not in the KEV: low
    ("negligible", False, False, True),         # Ubuntu
    ("Unimportant", False, False, True),
    ("unimportant", True, False, False),        # exposed: the table decides
    ("unimportant", False, True, False),        # in the KEV: the table decides
    ("unimportant", True, True, False),
    ("low", False, False, False),               # another rating
    ("not yet assigned", False, False, False),
    (None, False, False, False),
    ("end-of-life", False, False, False),
])
def test_the_vendor_rating_lowers_a_cve_only_when_not_exposed_and_not_in_the_kev(urgency, exposed, kev, lowered):
    c = cve(kev, True, "total", urgency=urgency)          # row 13 (or higher): 60 days or more without the rule
    r = priority.rate(c, exposed, 0.04)
    assert r.vendor_lowered is lowered
    if lowered:
        assert (r.days, r.severity, r.triage, r.row) == (None, "low", False, 13) and r.deadline == "Fix at the next upgrade"
        assert "lowered by the vendor's rating" in priority.basis_text(r)
    else:
        assert r.days is not None and r.severity != "low"


# --- ordering and the worst CVE --------------------------------------------------------------------------------------------------

def test_cves_sort_by_the_table_then_epss_and_an_update_takes_the_worst():
    cves = [
        {"cve": "CVE-1", "kev": False, "epss": 0.9, "automatable": "no", "impact": "partial", "state": "fix"},     # exposed: row 8, 60 days
        {"cve": "CVE-2", "kev": True, "epss": 0.1, "automatable": "yes", "impact": "partial", "state": "fix"},    # row 2, 3 days
        {"cve": "CVE-3", "kev": False, "epss": 0.5, "automatable": "yes", "impact": "partial", "state": "fix"},   # row 6, 14 days
        {"cve": "CVE-4", "kev": False, "epss": 0.2, "automatable": "yes", "impact": "partial", "state": "fix"},   # row 6, 14 days
        {"cve": "CVE-5", "kev": True, "epss": 0.1, "automatable": "yes", "impact": "total", "state": "fix"},      # row 1, 3 days and triage
    ]
    priority.attach(cves, True, 0.04)
    assert [c["cve"] for c in cves] == ["CVE-5", "CVE-2", "CVE-3", "CVE-4", "CVE-1"]      # triage first, then 14 days by EPSS
    assert priority.worst(c["rating"] for c in cves) is cves[0]["rating"] and priority.worst([]) is None
    assert [priority.worse_severity(a, b) for a, b in (("low", "high"), ("critical", "medium"), (None, "low"), ("medium", None))] == ["high", "critical", "low", "medium"]


def test_epss_is_shown_as_a_probability_with_its_percentile():
    assert priority.epss_text(0.153, 0.92) == "15.3% (92nd)"
    assert priority.epss_text(0.82641, 0.99673) == "82.6% (100th)"
    assert priority.epss_text(0.0066, 0.521) == "0.7% (52nd)"
    assert priority.epss_text(0.0003, 0.011) == "under 0.1% (1st)"
    assert priority.epss_text(0.1, 0.22) == "10.0% (22nd)" and priority.epss_text(0.1, 0.12) == "10.0% (12th)" and priority.epss_text(0.1, 0.23) == "10.0% (23rd)"
    assert priority.epss_text(0.5, None) == "50.0%" and priority.epss_text(None, None) == "no EPSS score"
    assert match.pct(0.153, 0.92) == "15.3% (92nd)"


# --- the table file --------------------------------------------------------------------------------------------------------------

def doc():
    return json.loads(BUNDLED.read_text())


def test_the_bundled_file_is_the_whole_of_table_1_and_names_the_directive():
    t = priority.parse(doc())
    assert (t.version, t.name, t.table_name, t.source) == (1, "CISA BOD 26-04", "Table 1", "bundled")
    assert t.date == "2026-06-10" and t.url.startswith("https://www.cisa.gov/") and t.table_url.endswith("BOD_26-04_Table_1_Remediation_Timelines_0.png")
    assert len(t.rows) == 16 and t.severity == SEVERITY and len(t.triage_steps) == 5
    for n, (e, k, a, i, days, triage) in TABLE_1.items():
        row = t.lookup(e == "Y", k == "Y", a == "Y", i)
        assert (row.row, row.days, row.triage) == (n, days, triage)
    assert priority.bundled().name == "CISA BOD 26-04"


def bad(mutate):
    d = doc()
    mutate(d)
    with pytest.raises(priority.TableError) as exc:
        priority.parse(d)
    return str(exc.value)


def test_a_file_that_is_not_exactly_the_format_is_refused():
    assert "missing keys ['rows']" in bad(lambda d: d.pop("rows"))
    assert "unknown keys ['extra']" in bad(lambda d: d.update(extra=1))                                  # an extra key
    assert "directive has unknown keys ['x']" in bad(lambda d: d["directive"].update(x="y"))
    assert "row 3 has unknown keys ['note']" in bad(lambda d: d["rows"][2].update(note="x"))
    assert "must be a list of 16 rows" in bad(lambda d: d["rows"].pop())                                  # a missing row
    msg = bad(lambda d: d["rows"][15].update(exposed="yes", kev="yes", automatable="yes", impact="total"))
    assert "repeats the inputs of another row" in msg
    assert "is not one of ['critical', 'high', 'medium', 'low']" in bad(lambda d: d["severity"].update({"3": "urgent"}))   # an unknown severity
    assert "severity must map exactly the timelines the rows use" in bad(lambda d: d["severity"].pop("60"))
    assert "severity must map exactly the timelines the rows use" in bad(lambda d: d["severity"].update({"30": "high"}))
    assert "severity key 'soon' must be" in bad(lambda d: d["severity"].update(soon="low"))
    assert "row 2: exposed must be one of" in bad(lambda d: d["rows"][1].update(exposed="maybe"))
    assert "triage must be true or false" in bad(lambda d: d["rows"][0].update(triage="yes"))
    assert "days must be a whole number" in bad(lambda d: d["rows"][0].update(days=3.5))
    assert "days must be a whole number" in bad(lambda d: d["rows"][0].update(days=True))
    assert "days must be a whole number" in bad(lambda d: d["rows"][0].update(days=0))
    assert "version must be a whole number" in bad(lambda d: d.update(version="1"))
    assert "inputs.impact must list exactly" in bad(lambda d: d["inputs"].update(impact=["total", "partial", "none"]))
    assert "must be an https address" in bad(lambda d: d["directive"].update(url="http://www.cisa.gov/x"))
    assert "must be an https address" in bad(lambda d: d["directive"].update(table_url="javascript:alert(1)"))
    assert "directive.date must be YYYY-MM-DD" in bad(lambda d: d["directive"].update(date="June 10"))
    assert "must be a short text" in bad(lambda d: d["directive"].update(name=""))
    assert "must be a short text" in bad(lambda d: d["directive"].update(name="x" * 200))
    assert "must be a short text" in bad(lambda d: d["rows"][0].update(timeline="a\nb"))
    assert "triage_steps must be a list" in bad(lambda d: d.update(triage_steps=[]))
    with pytest.raises(priority.TableError, match="the file must be an object"):
        priority.parse([])


def test_the_file_is_data_only_nothing_in_it_is_run_or_expanded():
    d = doc()
    d["directive"]["name"] = "CISA BOD 27-01 {{ 7*7 }} ${x} %(y)s"
    t = priority.parse(d)
    r = priority.rate(cve(False, False, "partial"), False, 0.04, t)
    assert r.directive == "CISA BOD 27-01 {{ 7*7 }} ${x} %(y)s"            # carried as plain text
    assert priority.basis_text(r).startswith("CISA BOD 27-01 {{ 7*7 }} ${x} %(y)s Table 1 row 16")


def put_override(data_dir, text):
    p = Path(data_dir) / priority.OVERRIDE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_a_valid_override_is_preferred_and_names_its_own_directive(tmp_path):
    assert priority.load(tmp_path).source == "bundled" and priority.load(None).source == "bundled"
    d = doc()
    d["version"] = 2
    d["directive"].update(name="CISA BOD 27-01", table_name="Table A", date="2027-02-01")
    d["rows"][15].update(days=90, timeline="90 days")      # the new directive gives "fix on upgrade" a deadline
    d["severity"] = {"3": "critical", "14": "high", "60": "medium", "90": "low"}
    d["rows"][14].update(days=90, timeline="90 days")
    p = put_override(tmp_path, json.dumps(d))
    t = priority.load(tmp_path)
    assert (t.version, t.name, t.source) == (2, "CISA BOD 27-01", str(p))
    r = priority.rate(cve(False, False, "partial"), False, 0.04, t)
    assert (r.days, r.severity, r.directive, r.table_name) == (90, "low", "CISA BOD 27-01", "Table A")
    assert r.deadline == "Fix within 90 days (CISA BOD 27-01 timeline)" and "CISA BOD 27-01 Table A row 16: 90 days" in priority.basis_text(r)
    priority.use(tmp_path)
    assert priority.rate(cve(False, False, "partial"), False, 0.04).days == 90            # the default for rate() follows use()
    assert priority.attach([{"cve": "C", "kev": False, "epss": 0, "automatable": "no", "impact": "partial"}], False, 0.04)[0]["rating"].directive == "CISA BOD 27-01"
    # The file changes: the new one is read; removed: back to the bundled table.
    d["version"] = 3
    put_override(tmp_path, json.dumps(d))
    assert priority.load(tmp_path).version == 3
    p.unlink()
    assert priority.load(tmp_path).source == "bundled"
    priority.use(None)
    assert priority.rate(cve(False, False, "partial"), False, 0.04).days is None


@pytest.mark.parametrize("text", ["not json", "[]", "{}", '{"version": 2}', "x" * 70000, "�"])
def test_an_invalid_override_is_refused_logged_once_and_the_bundled_table_is_used(tmp_path, caplog, text):
    caplog.set_level(logging.WARNING, logger="daemonsight.priority")
    put_override(tmp_path, text)
    assert priority.load(tmp_path).source == "bundled" and priority.load(tmp_path).source == "bundled"
    assert caplog.text.count("Ignoring") == 1 and "Using the bundled bod-26-04.json table" in caplog.text


def test_an_override_with_one_row_missing_is_refused(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="daemonsight.priority")
    d = doc()
    d["rows"].pop(0)
    put_override(tmp_path, json.dumps(d))
    assert priority.load(tmp_path).name == "CISA BOD 26-04" and "must be a list of 16 rows" in caplog.text


def test_an_override_that_is_not_a_readable_file_is_refused(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="daemonsight.priority")
    p = tmp_path / priority.OVERRIDE
    p.mkdir(parents=True)                       # a directory where the file should be
    assert priority.load(tmp_path).source == "bundled" and "cannot read it" in caplog.text


def test_findings_name_the_directive_from_the_file_not_from_code(tmp_path):
    from daemonsight.cve import exposure
    d = doc()
    d["directive"].update(name="CISA BOD 27-01", table_name="Table 9")
    t = priority.parse(d)
    cves = [{"source": "brotli", "cve": "CVE-2026-1", "state": "fix", "installed": "1", "fixed": "2", "urgency": None, "epss": 0.5,
             "pctile": 0.9, "kev": True, "automatable": "yes", "impact": "total", "descr": ""}]
    priority.attach(cves, True, 0.04, t)
    lead, lines = match.finding_text(cves[0], "test")
    assert "CISA BOD 27-01 timeline" in lead and "CISA BOD 27-01 Table 9 row 1" in lead and "BOD 26-04" not in lead + " ".join(lines)
    priority._current = t
    try:
        f = match.package_findings(copy.deepcopy(cves), {}, set(), exposure.Exposure(True, "test"), 0.04)[0]
    finally:
        priority._current = None
    assert "CISA BOD 27-01" in f.detail and "CISA BOD 27-01" in f.howto and "BOD 26-04" not in f.detail + f.howto


def test_table_sha256_is_optional_and_checked():
    import json as _json
    from importlib import resources
    doc = _json.loads(resources.files("daemonsight.data").joinpath("priority", priority.BUNDLED).read_text())
    assert len(priority.parse(doc).table_sha256) == 64
    del doc["directive"]["table_sha256"]
    assert priority.parse(doc).table_sha256 == ""
    for bad in ("ABC", "g" * 64, 5, "A" * 64):
        doc["directive"]["table_sha256"] = bad
        with pytest.raises(priority.TableError, match="table_sha256"):
            priority.parse(doc)
    doc["directive"]["unknown"] = "x"
    del doc["directive"]["table_sha256"]
    with pytest.raises(priority.TableError, match="unknown keys"):
        priority.parse(doc)
