"""The two places the hub asks for the CVE ids of an OPNsense changelog's security advisories, for tests: FreeBSD's advisory
files (www.freebsd.org/security/advisories/FreeBSD-SA-<id>.asc) and GitHub's repository advisory API
(api.github.com/repos/opnsense/core/security-advisories/<id>).

The data is real, fetched on 2026-11-24 (tests/fixtures/opnsense/advisories/): sa-26.json holds the Topic and the "CVE Name:"
line of the 21 FreeBSD advisories OPNsense 26.7.10 lists (SA-26:74 to 26:94), and one JSON file each for the two GitHub
advisories of 26.7.10 (no CVE id, rated high) and for GHSA-2v2x-m4j7-76pv, which has one. An advisory the fixtures do not
hold is a 404, as the real sites answer for an unknown id."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

FIX = Path(__file__).parent / "fixtures" / "opnsense" / "advisories"
SA = json.loads((FIX / "sa-26.json").read_text())
SA_HOST = "www.freebsd.org"
GH_HOST = "api.github.com"

# The CVE ids of all 21 FreeBSD advisories and the number of them (26.7.10 fixes 27 through FreeBSD).
SA_CVES = {ref: re.findall(r"CVE-\d{4}-\d{4,10}", v["cve_name"]) for ref, v in SA.items()}
SA_CVE_COUNT = sum(len(v) for v in SA_CVES.values())


def sa_text(ref: str, cve_name: str | None = None) -> str:
    """An advisory in FreeBSD's layout (header block, then sections), made from the real Topic and CVE Name."""
    v = SA[ref]
    cve = v["cve_name"] if cve_name is None else cve_name
    return (f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{'=' * 77}\nFreeBSD-SA-{ref}"
            f"{'Security Advisory':>{59 - len(ref)}}\n{'The FreeBSD Project':>73}\n\nTopic:          {v['topic']}\n\n"
            "Category:       core\nModule:         x\nAnnounced:      2026-11-17\nAffects:        All supported versions of FreeBSD.\n"
            + (f"CVE Name:       {cve}\n" if cve else "") + "\nFor general information regarding FreeBSD Security Advisories,\n"
            "including descriptions of the fields above, see <URL:https://security.FreeBSD.org/>.\n\nI.   Background\n\nText.\n")


def handler(request: httpx.Request, calls: list | None = None) -> httpx.Response | None:
    """The answer for a request to either host, or None for any other host."""
    if request.url.host not in (SA_HOST, GH_HOST):
        return None
    if calls is not None:
        calls.append((request.url.host, request.url.path))
    assert request.url.scheme == "https"
    if request.url.host == SA_HOST:
        m = re.fullmatch(r"/security/advisories/FreeBSD-SA-(\d{2}:\d+\.\w+)\.asc", request.url.path)
        if m and m.group(1) in SA:
            return httpx.Response(200, text=sa_text(m.group(1)), headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")
    assert request.headers["accept"] == "application/vnd.github+json"
    m = re.fullmatch(r"/repos/opnsense/core/security-advisories/(GHSA(?:-[a-z0-9]{4}){3})", request.url.path)
    f = FIX / f"{m.group(1)}.json" if m else None
    if f is not None and f.exists():
        return httpx.Response(200, content=f.read_bytes(), headers={"content-type": "application/json", "x-ratelimit-limit": "60",
                                                                      "x-ratelimit-remaining": "50", "x-ratelimit-reset": "1795003600"})
    return httpx.Response(404, json={"message": "Not Found", "status": "404"})
