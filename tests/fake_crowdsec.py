"""A fake CrowdSec Local API for tests: an httpx MockTransport that behaves like `GET /v1/decisions` in CrowdSec's source
(pkg/apiserver/controllers/v1/decisions.go, pkg/database/decisionfilter.go) and records every request.

What it copies from the source: `X-Api-Key` is checked and a wrong or missing key is 403 {"message": "access forbidden"};
`ip` and `range` match by address range (`contains` defaults to true: the decision contains the query; false: the decision
lies inside it); `origins` and `limit` filter; and, as the real one does, a request with no `ip`, `range` or `origins`
answers EVERY decision, which the fake records in `unfiltered` so a test can prove the hub never asks that. An empty
answer is JSON `null`, as `FormatDecisions` gives for a nil slice. `/v1/decisions/stream` is recorded in `streamed`.
Everything here is made up: documentation addresses only."""

import ipaddress
import json

import httpx

from daemonsight.remote.client import Net

KEY = "SYNTHETICBOUNCERKEY0123456789abcdef"


def decision(value: str, scenario="firewallservices/pf-scan-multi_ports", origin="crowdsec", type_="ban", duration="3h59m12.5s",
             id_=1, scope=None) -> dict:
    scope = scope or ("Range" if "/" in value else "Ip")
    return {"id": id_, "origin": origin, "scenario": scenario, "scope": scope, "type": type_, "value": value, "duration": duration}


class FakeLapi:
    def __init__(self, key: str = KEY, decisions: list[dict] | None = None):
        self.key = key
        self.decisions = list(decisions or [])
        self.requests: list[httpx.Request] = []
        self.unfiltered: list[httpx.Request] = []
        self.streamed: list[httpx.Request] = []
        self.fail: Exception | None = None
        self.status: int | None = None
        # A big community blocklist sits in the same database, as on a real firewall: a read that is not filtered by an
        # address would return all of it.
        self.community = [decision(f"198.18.{i // 250}.{i % 250}", scenario="", origin="CAPI", id_=1000 + i) for i in range(2000)]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            raise self.fail
        if request.url.path == "/v1/decisions/stream":
            self.streamed.append(request)
            return httpx.Response(200, json={"new": self.community, "deleted": None})
        if request.method != "GET" or request.url.path != "/v1/decisions":
            return httpx.Response(404, json={"message": "no"})
        if request.headers.get("x-api-key") != self.key:
            return httpx.Response(403, json={"message": "access forbidden"})
        if self.status:
            return httpx.Response(self.status, json={"message": "nope"})
        q = dict(request.url.params)
        rows = self.decisions + self.community
        if "ip" in q or "range" in q:
            try:
                want = ipaddress.ip_network(q.get("ip") or q["range"], strict=False)
            except ValueError:
                return httpx.Response(400, json={"message": "invalid ip address"})
            contains = q.get("contains", "true") == "true"
            rows = [d for d in rows if _match(d["value"], want, contains)]
        elif "origins" not in q:
            self.unfiltered.append(request)
        if "origins" in q:
            rows = [d for d in rows if d["origin"] in q["origins"].split(",")]
        if "limit" in q:
            rows = rows[:int(q["limit"])]
        return httpx.Response(200, content=json.dumps(rows or None), headers={"content-type": "application/json"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler), timeout=5, follow_redirects=False)

    def queries(self) -> list[dict]:
        return [dict(r.url.params) for r in self.requests]

    def attach(self, net: Net) -> Net:
        net.lapi = self.client
        return net


def _match(value: str, want, contains: bool) -> bool:
    try:
        have = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    if have.version != want.version:
        return False
    return want.subnet_of(have) if contains else have.subnet_of(want)
