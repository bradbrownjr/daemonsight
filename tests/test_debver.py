"""Debian version comparison (cve/debver.py) against dpkg itself."""

import random
import shutil
import subprocess
from pathlib import Path

import pytest

from daemonsight.cve import debver

FIXTURE = Path(__file__).parent / "fixtures" / "cve" / "versions.txt"

# Orderings from Debian Policy 5.6.12 and dpkg's own test cases (lt means a < b).
ORDERED = [
    ("1.0", "1.0-1"), ("1.0~rc1", "1.0"), ("1.0~~", "1.0~"), ("1.0~", "1.0"), ("1.0", "1.0a"),
    ("1.0a", "1.0+"), ("1.2", "1.10"), ("1.9", "1.10"), ("0:9", "1:0"), ("2.0", "1:1.0"),
    ("1.0-1", "1.0-1+b1"), ("1.0-1~deb12u1", "1.0-1"), ("1.0-1", "1.0-1+deb12u1"),
    ("1.0-9", "1.0-10"), ("1.0-1", "1.0-1.1"), ("3.5.7-1~deb13u2", "3.5.7-1~deb13u3"),
    ("1.0.0", "1.0.0.1"), ("1.0a", "1.0b"), ("1.0.", "1.0.1"), ("1a", "1b"),
]
EQUAL = [("1.0", "1.0-0"), ("0:1.0", "1.0"), ("1.0-1", "1.0-01"), ("1.00", "1.0"), ("1", "1-0")]


@pytest.mark.parametrize("a,b", ORDERED)
def test_ordered(a, b):
    assert debver.compare(a, b) == -1
    assert debver.compare(b, a) == 1
    assert debver.lt(a, b)


@pytest.mark.parametrize("a,b", EQUAL)
def test_equal(a, b):
    assert debver.compare(a, b) == 0


def test_last_hyphen_starts_the_revision():
    assert debver.parse("1:2.3-4-5") == (1, "2.3-4", "5")
    assert debver.parse("2.3") == (0, "2.3", "0")


@pytest.mark.parametrize("bad", ["", "  ", "x:1.0", ":1.0", "1.0-", "-1", "1:0.23.0+dfsg-"])
def test_not_a_version(bad):
    with pytest.raises(ValueError):
        debver.compare(bad, "1.0")


@pytest.mark.skipif(not shutil.which("dpkg"), reason="dpkg not installed")
def test_matches_dpkg_on_real_versions():
    """Pairs of real tracker versions (a seeded sample, 600 pairs, plus every
    hand-written case above). The result must be the operator dpkg accepts.
    A run over 6,200 pairs from the whole tracker found no difference; see docs/DESIGN.md."""
    versions = [l.strip() for l in FIXTURE.read_text().splitlines() if l.strip() and not l.startswith("#")]
    assert len(versions) > 100
    rng = random.Random(3)
    pairs = [tuple(rng.sample(versions, 2)) for _ in range(600)] + ORDERED + EQUAL
    for a, b in pairs:
        try:
            op = {-1: "lt", 0: "eq", 1: "gt"}[debver.compare(a, b)]
        except ValueError:
            # The tracker has a few malformed versions; dpkg must refuse them too (exit 2).
            r = subprocess.run(["dpkg", "--compare-versions", a, "lt", b], capture_output=True)
            assert r.returncode == 2, f"{a} {b}: only we refuse"
            continue
        r = subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True)
        assert r.returncode == 0, f"{a} {op} {b}: dpkg disagrees"
