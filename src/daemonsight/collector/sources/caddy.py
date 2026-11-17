"""Caddy sites and upstreams from the admin API.

Field names are from Caddy v2.11.9's source:
  admin.go                     admin.listen (default "localhost:2019"), admin.disabled
  modules/caddyhttp/app.go     apps.http.servers{name: Server}
  modules/caddyhttp/server.go  Server.listen []string, .routes, .logs
  modules/caddyhttp/routes.go  Route.match (list of matcher sets), .handle, .terminal
  modules/caddyhttp/subroute.go  handler "subroute" with .routes
  modules/caddyhttp/reverseproxy/reverseproxy.go  .upstreams[].dial, .dynamic_upstreams
  modules/caddyhttp/reverseproxy/admin.go  GET /reverse_proxy/upstreams ->
      [{"address", "num_requests", "fails"}]
  matchers: host and path are string lists; remote_ip and client_ip are
      {"ranges": [...]}; not is a list of matcher sets.

The admin API checks the Host header against the listen address on TCP and
skips the check on a Unix socket (admin.go, allowedOrigins), so requests go to
the address exactly as configured. Only GET is ever sent.
"""

from __future__ import annotations

import ipaddress

import httpx

from . import Source, SourceUnavailable

IP_MATCHERS = ("remote_ip", "client_ip")
DENY_STATUSES = range(400, 500)


def parse_dial(dial: str) -> dict:
    """Split an upstream dial address into network, host and port.

    "localhost:8001", "10.6.26.2:80", "[::1]:9000", "unix//run/app.sock",
    and placeholders like "{http.request.host}:80" all occur in practice.
    """
    if "{" in dial:
        return {"network": "placeholder", "host": None, "port": None, "text": dial}
    for prefix in ("unix+h2c/", "unix/"):
        if dial.startswith(prefix):
            return {"network": "unix", "host": None, "port": None, "path": dial[len(prefix):], "text": dial}
    network = "tcp"
    addr = dial
    if "/" in dial.split(":", 1)[0]:
        network, addr = dial.split("/", 1)
    host, port = addr, None
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif addr.count(":") == 1:
        h, p = addr.split(":")
        if p.isdigit():
            host, port = h, int(p)
    return {"network": network, "host": host or None, "port": port, "text": dial}


def is_local(host: str | None, own_addresses: set[str]) -> bool:
    """True when an upstream host is this machine."""
    if host in (None, "", "localhost"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified or host in own_addresses


def _ranges(matcher_set: dict) -> list[tuple[str, list[str]]]:
    out = []
    for name in IP_MATCHERS:
        m = matcher_set.get(name)
        if isinstance(m, dict) and m.get("ranges"):
            out.append((name, list(m["ranges"])))
    return out


def _read_match(match: list | None) -> tuple[list[str], list[str], list[str], list[str]]:
    """Hosts, paths, allowed ranges and denied ranges from a route's matcher sets.

    Matcher sets are OR'd; fields within a set are AND'd. For a summary that's
    enough: collect everything any set names.
    """
    hosts, paths, allow, deny, other = [], [], [], [], []
    for ms in match or []:
        if not isinstance(ms, dict):
            continue
        # Matchers that narrow which requests a handler sees (a header or
        # method test, say), shown so a bot-only route doesn't look general.
        # "file" only tests whether a file exists, so it isn't one.
        other += [k for k in ms if k not in ("host", "path", "not", "file", *IP_MATCHERS) and k not in other]
        hosts += [h for h in ms.get("host", []) if isinstance(h, str)]
        paths += [p for p in ms.get("path", []) if isinstance(p, str)]
        for _, r in _ranges(ms):
            allow += r
        for inner in ms.get("not", []) or []:
            if isinstance(inner, dict):
                for _, r in _ranges(inner):
                    deny += r
    return hosts, paths, allow, deny, other


def _is_block(handlers: list) -> bool:
    """A route that refuses the request: abort, or a 4xx static response."""
    for h in handlers:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "static_response":
            if h.get("abort") or (isinstance(h.get("status_code"), int) and h["status_code"] in DENY_STATUSES) \
                    or str(h.get("status_code", "")).startswith("4"):
                return True
    return False


def _walk(routes: list, ctx: dict, out: list) -> None:
    # The Caddyfile's "root" directive becomes a vars handler that later
    # routes in the same list read, so it carries forward like this.
    root = ctx.get("root")
    for route in routes or []:
        if not isinstance(route, dict):
            continue
        hosts, paths, allow, deny, other = _read_match(route.get("match"))
        handlers = route.get("handle") or []
        for h in handlers:
            if isinstance(h, dict) and h.get("handler") == "vars" and isinstance(h.get("root"), str):
                root = h["root"]
        here = {
            "hosts": hosts or ctx["hosts"],
            "paths": paths or ctx["paths"],
            "allow": ctx["allow"] + allow,
            "when": ctx.get("when", []) + other,
            "server": ctx["server"],
            "listen": ctx["listen"],
            "root": root,
        }
        # "@outside not remote_ip 10.0.0.0/8; abort @outside" restricts the
        # whole site to the ranges it doesn't refuse.
        if deny and _is_block(handlers):
            ctx["site_allow"].extend(deny)
            continue
        for h in handlers:
            if not isinstance(h, dict):
                continue
            kind = h.get("handler")
            if kind == "subroute":
                # A route that names hosts starts a new site, so a block rule
                # inside it restricts that site only.
                _walk(h.get("routes"), {**here, "site_allow": [] if hosts else ctx["site_allow"]}, out)
            elif kind == "reverse_proxy":
                ups = [parse_dial(u.get("dial", "")) for u in h.get("upstreams") or [] if isinstance(u, dict)]
                out.append({**here, "kind": "proxy", "upstreams": ups,
                            "dynamic": bool(h.get("dynamic_upstreams")), "site_allow": ctx["site_allow"]})
            elif kind == "file_server":
                out.append({**here, "kind": "files", "root": h.get("root") or root, "upstreams": [],
                            "site_allow": ctx["site_allow"]})
            elif kind == "static_response":
                headers = h.get("headers") or {}
                loc = headers.get("Location") or headers.get("location")
                out.append({**here, "kind": "redirect" if loc else "respond",
                            "target": (loc or [None])[0] if isinstance(loc, list) else loc,
                            "status": h.get("status_code"), "upstreams": [], "site_allow": ctx["site_allow"]})


def parse_config(config: dict) -> dict:
    """Summarize a Caddy JSON config into sites and their handlers."""
    admin = config.get("admin") or {}
    http = ((config.get("apps") or {}).get("http") or {})
    entries: list[dict] = []
    servers = []
    for name, srv in (http.get("servers") or {}).items():
        listen = list(srv.get("listen") or [])
        logs = srv.get("logs")
        servers.append({
            "name": name, "listen": listen, "routes": len(srv.get("routes") or []),
            "access_log": logs is not None,
            "logged_hosts": sorted((logs or {}).get("logger_names", {}) or {}),
        })
        _walk(srv.get("routes"), {"hosts": [], "paths": [], "allow": [], "server": name,
                                  "listen": listen, "site_allow": []}, entries)
    # One site per (server, host): the same name can be served on two ports.
    sites: dict[tuple[str, str], dict] = {}
    for e in entries:
        for host in e["hosts"] or ["*"]:
            site = sites.setdefault((e["server"], host), {"host": host, "server": e["server"],
                                                          "listen": e["listen"], "handlers": [], "allow": []})
            allow = sorted(set(e["allow"] + e["site_allow"]))
            site["handlers"].append({"paths": e["paths"], "kind": e["kind"],
                                     "upstreams": e["upstreams"], "dynamic": e.get("dynamic", False),
                                     "root": e.get("root") if e["kind"] == "files" else None,
                                     "target": e.get("target"), "when": e.get("when", []),
                                     "status": e.get("status"), "allow": allow})
            for r in allow:
                if r not in site["allow"]:
                    site["allow"].append(r)
    return {
        "admin": {"listen": admin.get("listen") or "localhost:2019", "disabled": bool(admin.get("disabled"))},
        "servers": servers,
        "sites": sorted(sites.values(), key=lambda s: (s["host"], s["server"])),
    }


def admin_client(address: str, timeout: float = 10.0) -> httpx.AsyncClient:
    """An httpx client for a Caddy admin address ("localhost:2019",
    "unix//run/caddy/admin.sock", "tcp/127.0.0.1:2019")."""
    if address.startswith("unix/"):
        return httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=address[len("unix/"):]),
                                 base_url="http://localhost", timeout=timeout)
    if address.startswith("tcp/"):
        address = address[4:]
    return httpx.AsyncClient(base_url=f"http://{address}", timeout=timeout)


class CaddySource(Source):
    name = "caddy"

    def __init__(self, interval: int = 60, admin: str = "localhost:2019"):
        self.interval = interval
        self.admin = admin
        self._client: httpx.AsyncClient | None = None

    async def collect(self) -> dict:
        if self._client is None:
            self._client = admin_client(self.admin)
        try:
            r = await self._client.get("/config/")
        except (httpx.ConnectError, FileNotFoundError) as exc:
            raise SourceUnavailable(f"No Caddy admin API at {self.admin}") from exc
        r.raise_for_status()
        summary = parse_config(r.json() or {})
        try:
            u = await self._client.get("/reverse_proxy/upstreams")
            upstreams = u.json() if u.status_code == 200 else []
        except httpx.HTTPError:
            upstreams = []
        summary["upstream_status"] = [
            {"address": x.get("address"), "num_requests": x.get("num_requests"), "fails": x.get("fails")}
            for x in upstreams or [] if isinstance(x, dict)]
        summary["admin_address"] = self.admin
        return summary

    def metrics(self, data: dict) -> dict[str, float]:
        return {f"caddy.fails.{u['address']}": float(u["fails"] or 0)
                for u in data.get("upstream_status", []) if u.get("address")}

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
