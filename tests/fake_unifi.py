"""A fake UniFi Network controller for tests: an httpx MockTransport that serves synthetic replies in the shapes of
Ubiquiti's published OpenAPI document for UniFi Network 11.0.97 (made-up names, documentation addresses and MACs), checks
the X-API-KEY header, pages its lists like the real API (`offset`, `limit`, `totalCount`) and records every request. A
request that is not a GET, or that asks for a detail, action or client-identity path, is a test failure."""

import copy
import re

import httpx

from daemonsight.remote.client import Net

KEY = "SYNTHETICUNIFIKEY0123456789abcdefghijklmnopqrstuvwxyz"
SITE = "6b0c1f3e-0000-4000-8000-000000000001"
SITE2 = "6b0c1f3e-0000-4000-8000-000000000002"
DEV_AP1 = "9d1a0000-0000-4000-8000-000000000011"
DEV_AP2 = "9d1a0000-0000-4000-8000-000000000012"
DEV_SW = "9d1a0000-0000-4000-8000-000000000013"
DEV_GW = "9d1a0000-0000-4000-8000-000000000014"
WIFI_HOME = "3c2b0000-0000-4000-8000-000000000021"
WIFI_GUEST = "3c2b0000-0000-4000-8000-000000000022"
WIFI_OPEN = "3c2b0000-0000-4000-8000-000000000023"
ZONE_EXT = "4e5f0000-0000-4000-8000-000000000031"
ZONE_INT = "4e5f0000-0000-4000-8000-000000000032"
ZONE_GW = "4e5f0000-0000-4000-8000-000000000033"
POL_FWD = "5a6b0000-0000-4000-8000-000000000041"
POL_SYS = "5a6b0000-0000-4000-8000-000000000042"
POL_OUT = "5a6b0000-0000-4000-8000-000000000043"
PASSPHRASE = "SYNTHETIC-PASSPHRASE-must-never-be-stored"
PREFIX = "/proxy/network/integration"


def page(rows, offset=0, limit=200):
    return {"offset": offset, "limit": limit, "count": len(rows[offset:offset + limit]), "totalCount": len(rows),
            "data": rows[offset:offset + limit]}


def device(id_, name, model, features, state="ONLINE", firmware="6.6.55", updatable=False, ip="192.0.2.10", mac="00:00:5e:00:53:10"):
    return {"id": id_, "name": name, "model": model, "macAddress": mac, "ipAddress": ip, "state": state, "features": features,
            "interfaces": ["ports"], "firmwareVersion": firmware, "firmwareUpdatable": updatable, "supported": True}


def default_replies() -> dict:
    return {
        "info": {"applicationVersion": "10.1.89"},
        "sites": [{"id": SITE, "internalReference": "default", "name": "Default"}],
        "devices": {SITE: [
            device(DEV_AP1, "AP-Lobby", "U6-Lite", ["accessPoint"], updatable=True, ip="192.0.2.11", mac="00:00:5e:00:53:11"),
            device(DEV_AP2, "AP-Warehouse", "U6-Pro", ["accessPoint"], ip="192.0.2.12", mac="00:00:5e:00:53:12"),
            device(DEV_SW, "Switch-Closet", "USW-24-PoE", ["switching"], firmware="7.0.50", updatable=True, ip="192.0.2.13", mac="00:00:5e:00:53:13"),
        ]},
        "pending": [{"macAddress": "00:00:5e:00:53:77", "ipAddress": "192.0.2.77", "model": "U6-Mesh", "state": "PENDING_ADOPTION",
                     "firmwareVersion": "6.2.0", "firmwareUpdatable": False, "supported": True, "features": ["accessPoint"],
                     "adoptionTargetSiteIds": [SITE]}],
        "clients": {SITE: 7},
        "wifi": {SITE: [
            {"id": WIFI_HOME, "type": "STANDARD", "name": "Home", "enabled": True, "metadata": {"origin": "USER_DEFINED"},
             "network": {"type": "NATIVE"}, "broadcastingFrequenciesGHz": [2.4, 5],
             "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": PASSPHRASE, "presharedKeys": [{"passphrase": PASSPHRASE}]}},
            {"id": WIFI_GUEST, "type": "STANDARD", "name": "Guests", "enabled": True, "metadata": {"origin": "USER_DEFINED"},
             "network": {"type": "NATIVE"}, "broadcastingFrequenciesGHz": [2.4, 5], "hotspotConfiguration": {"type": "CAPTIVE_PORTAL"},
             "securityConfiguration": {"type": "OPEN"}},
        ]},
        "stats": {},
        "zones": {SITE: [{"id": ZONE_EXT, "name": "External", "networkIds": [], "metadata": {"origin": "SYSTEM_DEFINED"}},
                         {"id": ZONE_INT, "name": "Internal", "networkIds": [], "metadata": {"origin": "SYSTEM_DEFINED"}},
                         {"id": ZONE_GW, "name": "Gateway", "networkIds": [], "metadata": {"origin": "SYSTEM_DEFINED"}}]},
        "policies": {SITE: [
            {"id": POL_SYS, "name": "Block external to internal", "enabled": True, "index": 1, "action": {"type": "BLOCK"},
             "source": {"zoneId": ZONE_EXT}, "destination": {"zoneId": ZONE_INT}, "metadata": {"origin": "SYSTEM_DEFINED"}},
            {"id": POL_OUT, "name": "Allow internal to external", "enabled": True, "index": 2, "action": {"type": "ALLOW", "allowReturnTraffic": True},
             "source": {"zoneId": ZONE_INT}, "destination": {"zoneId": ZONE_EXT}, "metadata": {"origin": "SYSTEM_DEFINED"}},
        ]},
    }


def with_gateway(replies: dict, allow_in: bool = False) -> dict:
    replies["devices"][SITE].append(device(DEV_GW, "Gateway", "UCG-Max", ["gateway", "switching"], ip="192.0.2.1", mac="00:00:5e:00:53:01"))
    if allow_in:
        replies["policies"][SITE].append(
            {"id": POL_FWD, "name": "Web server", "enabled": True, "index": 3, "action": {"type": "ALLOW", "allowReturnTraffic": True},
             "source": {"zoneId": ZONE_EXT}, "destination": {"zoneId": ZONE_INT, "trafficFilter": {"type": "PORT", "portFilter": {"type": "PORTS"}}},
             "metadata": {"origin": "USER_DEFINED"}, "description": "Forward 443 to the web server at 198.51.100.20"})
    return replies


UUID = r"[0-9a-fA-F-]{36}"
ROUTES = [
    ("info", re.compile(rf"^{PREFIX}/v1/info$")),
    ("sites", re.compile(rf"^{PREFIX}/v1/sites$")),
    ("pending", re.compile(rf"^{PREFIX}/v1/pending-devices$")),
    ("devices", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/devices$")),
    ("stats", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/devices/({UUID})/statistics/latest$")),
    ("clients", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/clients$")),
    ("wifi", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/wifi/broadcasts$")),
    ("zones", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/firewall/zones$")),
    ("policies", re.compile(rf"^{PREFIX}/v1/sites/({UUID})/firewall/policies$")),
]


class FakeUnifi:
    """`replies` is `default_replies()`; a test edits it. `deny` is a set of route names that answer 403 (the admin may not
    read it)."""

    def __init__(self, key: str = KEY):
        self.key = key
        self.requests: list[httpx.Request] = []
        self.fail: Exception | None = None
        self.status: int | None = None
        self.deny: set[str] = set()
        self.server_cert: str | None = None
        self.replies = default_replies()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET", f"the hub sent {request.method} {request.url.path}"
        assert not request.content, "a GET to the controller carried a body"
        assert "content-type" not in request.headers, "a GET to the controller carried a Content-Type"
        assert "authorization" not in request.headers, "the key went in an Authorization header"
        if self.fail:
            raise self.fail
        if self.status:
            return httpx.Response(self.status, text="nope")
        if request.headers.get("x-api-key") != self.key:
            return httpx.Response(401, json={"statusCode": 401, "statusName": "UNAUTHORIZED", "message": "Unauthorized"})
        path = request.url.path
        for name, rx in ROUTES:
            m = rx.match(path)
            if not m:
                continue
            if name in self.deny:
                return httpx.Response(403, json={"statusCode": 403, "statusName": "FORBIDDEN", "message": "Forbidden"})
            q = dict(request.url.params)
            offset, limit = int(q.get("offset", 0)), int(q.get("limit", 25))
            site = m.group(1) if m.groups() else None
            r = self.replies
            if name == "info":
                return httpx.Response(200, json=copy.deepcopy(r["info"]))
            if name == "sites":
                return httpx.Response(200, json=page(copy.deepcopy(r["sites"]), offset, limit))
            if name == "pending":
                return httpx.Response(200, json=page(copy.deepcopy(r["pending"]), offset, limit))
            if name == "clients":
                total = r["clients"].get(site, 0)
                return httpx.Response(200, json={"offset": offset, "limit": limit, "count": 0, "totalCount": total, "data": []})
            if name == "stats":
                dev = m.group(2)
                if dev not in r["stats"]:
                    return httpx.Response(404, json={"message": "Not found"})
                return httpx.Response(200, json=copy.deepcopy(r["stats"][dev]))
            return httpx.Response(200, json=page(copy.deepcopy(r[name].get(site, [])), offset, limit))
        raise AssertionError(f"the hub asked for a path it should not: {request.url}")

    def paths(self) -> list[str]:
        return [r.url.path.removeprefix(PREFIX) for r in self.requests]

    def net(self) -> Net:
        fake = self

        class FakeNet(Net):
            def http(self_, tls="verify", pem=None):
                def handler(request):
                    if fake.server_cert is not None and (tls == "verify" or pem != fake.server_cert):
                        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                                 "self-signed certificate (_ssl.c:1029)")
                    return fake.handler(request)
                return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5, follow_redirects=False)

            async def certificate(self_, url):
                from daemonsight.remote.client import RemoteError
                if fake.server_cert is None:
                    raise RemoteError("unreachable", "no certificate")
                return fake.server_cert

        return FakeNet()
