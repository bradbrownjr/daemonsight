"""The CVE Services API (GET https://cveawg.mitre.org/api/cve/<CVE-ID>) for tests, shaped like the real records read on 2026-11-24
(CVE-2026-111497 and CVE-2021-44228): `cveMetadata`, `containers.cna` with its own `metrics`, and `containers.adp[]` whose
"CISA-ADP" entry carries the SSVC decision points as `metrics[].other` of type `ssvc` with `content.options`. The answers carry
the `ratelimit-*` headers the service sends (policy `25000;w=60`). A CVE not in RECORDS is a 404, as the service answers for an
unknown id. `CALLS` lists the CVE ids asked for."""

from __future__ import annotations

import json

import httpx

HOST = "cveawg.mitre.org"
CALLS: list[str] = []

# cve -> (Exploitation, Automatable, Technical Impact) as CISA rates them, or None for a record with no CISA-ADP container.
RATINGS: dict[str, tuple[str, str, str] | None] = {
    "CVE-2026-111497": ("active", "no", "total"),
}
# cve -> (cvss key, score, vector) the CNA gives, if any.
CVSS: dict[str, tuple[str, float, str]] = {
    "CVE-2026-111497": ("cvssV4_0", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
}
HEADERS = {"ratelimit-policy": "25000;w=60", "ratelimit-limit": "25000", "ratelimit-remaining": "24990", "ratelimit-reset": "45",
           "cache-control": "no-store", "etag": 'W/"x"'}
OVERRIDE: dict = {}      # tests: cve -> a ready httpx.Response (or a callable taking the request), to change an answer


def record(cve: str, rating=None, cvss=None, adp_name: str = "CISA-ADP") -> dict:
    cna: dict = {"providerMetadata": {"shortName": "mitre"}, "descriptions": [{"lang": "en", "value": "A flaw."}]}
    if cvss:
        key, score, vec = cvss
        cna["metrics"] = [{key: {"baseScore": score, "vectorString": vec, "version": key[4:].replace("_", ".")}}]
    adp = []
    if rating is not None:
        e, a, t = rating
        adp.append({"providerMetadata": {"shortName": adp_name}, "metrics": [
            {"other": {"type": "ssvc", "content": {"id": cve, "role": "CISA Coordinator", "version": "2.0.3",
                                                    "timestamp": "2026-11-20T12:00:00.000000Z",
                                                    "options": [{"Exploitation": e}, {"Automatable": a}, {"Technical Impact": t}]}}}]})
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
            "containers": {"cna": cna, "adp": adp}}


def handler(request: httpx.Request) -> httpx.Response | None:
    """The answer for a request to the service, or None for any other host."""
    if request.url.host != HOST:
        return None
    assert request.url.scheme == "https"
    cve = request.url.path.rsplit("/", 1)[-1]
    CALLS.append(cve)
    if cve in OVERRIDE:
        got = OVERRIDE[cve]
        return got(request) if callable(got) else got
    if cve not in RATINGS and cve not in CVSS:
        return httpx.Response(404, json={"error": "CVE_RECORD_DNE", "message": "The CVE record does not exist or is not available."},
                              headers=HEADERS)
    return httpx.Response(200, content=json.dumps(record(cve, RATINGS.get(cve), CVSS.get(cve))).encode(),
                          headers={**HEADERS, "content-type": "application/json; charset=utf-8"})
