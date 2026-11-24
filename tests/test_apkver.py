"""Alpine version comparison (cve/apkver.py) against apk-tools' own test table and the rules in its version.c."""

from pathlib import Path

import pytest

from daemonsight.cve import apkver

TABLE = Path(__file__).parent / "fixtures" / "cve" / "apk-version.data"


def _lines():
    for n, raw in enumerate(TABLE.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if line:
            yield n, line


def _holds(op: str, r: int) -> bool:
    """apk_version_match: the result r (-1, 0, 1) against an operator made of <, > and =."""
    return (("<" in op and r < 0) or ("=" in op and r == 0) or (">" in op and r > 0))


def test_the_table_is_apk_tools_own_and_whole():
    lines = list(_lines())
    assert len(lines) > 650
    assert sum(1 for _n, l in lines if l.startswith("!")) >= 20 and any(len(l.split()) == 3 for _n, l in lines)


@pytest.mark.parametrize("n,line", list(_lines()))
def test_apk_tools_version_table(n, line):
    parts = line.split(" ")
    if len(parts) == 3:
        a, op, b = parts
        if "~" in op:
            pytest.skip("fuzzy dependency match, not used")
        invert = op.startswith("!")
        assert _holds(op.lstrip("!"), apkver.compare(a, b)) != invert, f"line {n}: {line}"
    else:
        (v,) = parts
        invert = v.startswith("!")
        assert apkver.valid(v.lstrip("!")) != invert, f"line {n}: {line}"


@pytest.mark.parametrize("lo,hi", [
    ("1.0_alpha", "1.0_beta"), ("1.0_beta", "1.0_pre"), ("1.0_pre", "1.0_rc"), ("1.0_rc1", "1.0"), ("1.0", "1.0_cvs"),
    ("1.0_cvs", "1.0_svn"), ("1.0_svn", "1.0_git"), ("1.0_git", "1.0_hg"), ("1.0_hg", "1.0_p"), ("1.0_p1", "1.0_p2"),
    ("1.0", "1.0-r1"), ("1.0-r1", "1.0-r2"), ("1.0-r9", "1.0-r10"), ("1.2", "1.10"), ("1.2.9", "1.2.10"),
    ("1.0", "1.0a"), ("1.0a", "1.0b"), ("1.0.4", "1.0.4a"), ("1.0_rc1-r5", "1.0-r0"), ("3.5.4-r0", "3.5.5-r0"),
    ("3.5.4-r9", "3.6.0-r0"), ("1.2.13-r0", "1.2.13-r1"), ("1.1.1w-r0", "3.0.0-r0"), ("0.9.8-r0", "1.0.0-r0"),
    ("1.0_alpha1", "1.0_alpha2"), ("1.0_git20240101", "1.0_git20240201"), ("1.0~abc", "1.0~abd"), ("1.02", "1.1"),
])
def test_documented_order(lo, hi):
    assert apkver.valid(lo) and apkver.valid(hi)
    assert apkver.compare(lo, hi) == -1 and apkver.compare(hi, lo) == 1 and apkver.lt(lo, hi) and not apkver.lt(hi, lo)


def test_equal_versions_and_a_missing_revision():
    assert apkver.compare("1.2.3-r4", "1.2.3-r4") == 0
    assert apkver.compare("1.2.3", "1.2.3") == 0
    assert apkver.compare("1.2.3", "1.2.3-r0") == -1          # a revision, even r0, is something more


@pytest.mark.parametrize("bad", ["", "a", ".1", "1.", "1..2", "1_foo", "1_", "1a1", "1ab", "1-r", "1-r1-r2", "1-r1_rc1", "1~", "1~xyz",
                                 "1_rc1~abc_p1", "1 2", "1.2-3", "18446744073709551616", "1.2.3_rc1.1", "-r1", "1\x00"])
def test_versions_apk_refuses(bad):
    assert not apkver.valid(bad)


@pytest.mark.parametrize("good", ["1", "1.2.3", "3.5.4-r0", "1.1.1w-r0", "20240101-r0", "1.0_rc1", "1.0_alpha_pre2", "1.0~abc123-r1",
                                  "18446744073709551615", "2.5.1a-r1"])
def test_versions_apk_accepts(good):
    assert apkver.valid(good)


def test_a_number_with_a_leading_zero_compares_as_text():
    # version.c token_cmp: if either side's digits start with 0, the digits are sorted as strings.
    assert apkver.compare("1.02", "1.1") == -1                # "02" < "1" as text; 2 < 1 would say the opposite
    assert apkver.compare("1.10", "1.9") == 1                 # no zero: numeric
    assert apkver.compare("1.01", "1.1") == -1
    assert apkver.compare("8.2.0", "8.2.001") == -1
