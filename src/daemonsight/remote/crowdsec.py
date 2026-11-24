"""CrowdSec bans on an OPNsense firewall, as the hub reads them from CrowdSec's Local API (LAPI), and the findings.

Why. On 2026-11-19 the firewall's CrowdSec banned the firewall's own WAN address twice (scenario
firewallservices/pf-scan-multi_ports). Its pf bouncer kills the states of a banned address, so every NAT'd connection
on the LAN dropped, and the cascade got Anthropic's API address banned for four hours. DaemonSight shows such a ban
as a finding instead of leaving it to be found through an outage. docs/DESIGN.md, "CrowdSec", has the sources.

What is read, and nothing else. One endpoint, `GET /v1/decisions`, with a bouncer's API key in `X-Api-Key`
(CrowdSec's authentication page: API keys "can only read decisions"; the router puts `GET /decisions` in the API-key
group and every write and `/alerts` in the machine (JWT) group). Every call carries a filter:

* `ip=<address>` for one address (CrowdSec's `contains` defaults to true: decisions that contain it, a range ban
  included);
* `range=<cidr>&contains=true` for a ban that covers a whole network, and `contains=false` for a ban inside it;
* `origins=crowdsec` for the local decisions, with `limit`.

`/v1/decisions/stream` is never called (it moves the bouncer's pull state and returns the whole community blocklist),
and a call with no `ip`, `range` or `origins` is refused here, because CrowdSec answers that with every decision it
has (`applyDecisionFilter` applies no address filter when none is given). `Lapi.check_params` enforces all of this
before anything is sent.

An empty answer is JSON `null`, not `[]` (`FormatDecisions` returns a nil slice); both are read as no decisions.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ..findings import Finding
from .client import MAX_RESPONSE, USER_AGENT, RemoteError, scrub
from .store import NEVER_MIN_PREFIX

SNAPSHOT = "opnsense_crowdsec"
LINK = "/firewall#crowdsec"
PATH = "/v1/decisions"
READ_EVERY = 120                # seconds: the hub asks CrowdSec at most this often
ROWS_PER_QUERY = 50             # `limit` on an address query
LOCAL_ROWS = 500                # decisions read for the local count (origins=crowdsec)
LOCAL_SCENARIOS_KEPT = 20
BANS_KEPT = 10                  # decisions kept per protected address
MAX_QUERIES = 160
PARALLEL = 4
UNREACHABLE_AFTER_FAILS = 2     # reads in a row that fail before crowdsec.unreachable opens
URL_HELP = "Give CrowdSec's Local API address, for example http://192.168.1.1:8180 (the api_url in the bouncer's config)."
ALLOWED_PARAMS = frozenset({"ip", "range", "contains", "origins", "limit"})
LOCAL_ORIGIN = "crowdsec"       # the origin of a decision a local scenario made (pkg/types/constants.go: CrowdSecOrigin)


# --- the client -------------------------------------------------------------------------------------------------------

def normalize_url(raw: str) -> str:
    """The Local API's origin, `http(s)://host[:port]`. http is the default: CrowdSec's LAPI listens on plain http
    unless TLS is set up in its config (docs/SECURITY.md)."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 300 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError(URL_HELP)
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ValueError("That address isn't valid.") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The address must start with http:// or https://.")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("Give only the address and port; leave out any path, user name, password or query.")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def _net(text: str):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


class Lapi:
    """CrowdSec's Local API, read-only on this side: `get` sends a GET of `/v1/decisions` with a checked filter and
    nothing else (see `check_params`). The bouncer key goes in `X-Api-Key`. No redirects, a reply capped at
    MAX_RESPONSE, the key scrubbed from every message."""

    def __init__(self, base_url: str, key: str, http: httpx.AsyncClient):
        self.base = base_url.rstrip("/")
        self._key = key
        self._http = http
        self._headers = {"X-Api-Key": key, "Accept": "application/json", "User-Agent": USER_AGENT}

    async def aclose(self) -> None:
        await self._http.aclose()

    @staticmethod
    def check_params(params: dict) -> None:
        """Refuse anything that is not one of the three filtered reads (see the module doc). Raises ValueError."""
        if not isinstance(params, dict) or not set(params) <= ALLOWED_PARAMS:
            raise ValueError("only ip, range, contains, origins and limit may be sent")
        limit = params.get("limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LOCAL_ROWS:
            raise ValueError("every read needs a limit")
        filters = [k for k in ("ip", "range", "origins") if k in params]
        if len(filters) != 1:
            raise ValueError("every read needs exactly one of ip, range or origins: never all decisions")
        if "ip" in params:
            try:
                ipaddress.ip_address(str(params["ip"]))
            except ValueError:
                raise ValueError("ip must be one IP address") from None
            if "contains" in params:
                raise ValueError("contains goes with range only")
        elif "range" in params:
            value = str(params["range"])
            net = _net(value) if "/" in value else None
            if net is None or params.get("contains") not in ("true", "false"):
                raise ValueError("range must be a network, with contains true or false")
            # What lies inside a very wide public range could be a large part of the community blocklist.
            if params["contains"] == "false" and not net.is_private and net.prefixlen < NEVER_MIN_PREFIX[net.version]:
                raise ValueError("that range is too wide to ask what lies inside it")
        else:
            if params["origins"] != LOCAL_ORIGIN or "contains" in params:
                raise ValueError("origins may only be crowdsec")

    async def get(self, params: dict) -> list[dict]:
        """GET /v1/decisions?<params> and return the decisions (a list; CrowdSec answers null for none). Raises
        RemoteError: auth (403), http, unreachable, tls."""
        self.check_params(params)
        query = {k: ("true" if v is True else "false" if v is False else v) for k, v in params.items()}
        try:
            async with self._http.stream("GET", self.base + PATH, params=query, headers=self._headers) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise RemoteError("http", "CrowdSec's reply was larger than 8 MiB; ignored.", PATH)
                status = r.status_code
        except RemoteError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        if 300 <= status < 400:
            raise RemoteError("http", "CrowdSec redirected the request. Redirects are not followed (the key would "
                                      "go to the new address).", PATH)
        if status in (401, 403):
            raise RemoteError("auth", f"CrowdSec refused the bouncer key (HTTP {status}). Check the key, and that "
                                      "the bouncer still exists (cscli bouncers list).", PATH)
        if status == 400:
            raise RemoteError("http", "CrowdSec did not accept the query (HTTP 400).", PATH)
        if status != 200:
            raise RemoteError("http", f"CrowdSec answered HTTP {status}.", PATH)
        try:
            data = json.loads(body)
        except ValueError:
            raise RemoteError("http", "CrowdSec's reply was not JSON.", PATH) from None
        if data is None:
            return []
        if not isinstance(data, list):
            raise RemoteError("http", "CrowdSec's reply was not a list of decisions.", PATH)
        return [d for d in data if isinstance(d, dict)]

    def _transport_error(self, exc: httpx.HTTPError) -> RemoteError:
        clip = "".join(c for c in scrub(str(exc), self._key)[:200] if c.isprintable())
        if isinstance(exc, httpx.ConnectError) and ("CERTIFICATE_VERIFY_FAILED" in clip or "certificate" in clip.lower()):
            return RemoteError("tls", "CrowdSec's certificate was not accepted: " + clip + " Use the address its "
                                                                                          "certificate names, or http:// if TLS is off.", PATH)
        if isinstance(exc, httpx.TimeoutException):
            return RemoteError("unreachable", "CrowdSec did not answer in time.", PATH)
        if isinstance(exc, httpx.ConnectError):
            return RemoteError("unreachable", "Could not connect to CrowdSec: " + clip, PATH)
        return RemoteError("unreachable", f"{type(exc).__name__}: {clip}", PATH)


def error_text(exc: Exception, key: str | None) -> str:
    return scrub(exc.message if isinstance(exc, RemoteError) else f"{type(exc).__name__}: {exc}", key)[:300]


@dataclass
class Probe:
    local: int          # local decisions seen (at most 1: the test asks for one row)


async def probe(net, url: str, key: str) -> Probe:
    """Ask for one local decision: proves the address, the key and that the key can read decisions. Raises RemoteError."""
    lapi = Lapi(url, key, net.lapi())
    try:
        rows = await lapi.get({"origins": LOCAL_ORIGIN, "limit": 1})
    finally:
        await lapi.aclose()
    return Probe(len(rows))


# --- decisions -------------------------------------------------------------------------------------------------------

_GO_DURATION = re.compile(r"(\d+(?:\.\d+)?)(h|ms|m|s)")


def parse_duration(text) -> float | None:
    """Seconds in a Go duration string such as "3h59m12.5s", or None. CrowdSec's `duration` on GET /decisions is
    the time left until the decision ends (`FormatDecisions`: until minus now)."""
    s = str(text or "").strip()
    if not s or s.startswith("-"):
        return None
    total = sum(float(m.group(1)) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[m.group(2)] for m in _GO_DURATION.finditer(s))
    return total if not _GO_DURATION.sub("", s).strip() else None


def _text(v, n: int = 200) -> str:
    return "".join(c for c in str(v if v is not None else "")[:n] if c.isprintable()).strip()


def trim_decision(d: dict) -> dict | None:
    """The fields kept from one decision (Decision in localapi_swagger.yaml), cut to size. None when it names no value."""
    value = _text(d.get("value"), 60)
    if not value:
        return None
    return {"id": d.get("id") if isinstance(d.get("id"), int) and not isinstance(d.get("id"), bool) else None,
            "origin": _text(d.get("origin"), 30), "scenario": _text(d.get("scenario"), 120), "value": value,
            "scope": _text(d.get("scope"), 20), "type": _text(d.get("type"), 20).lower(),
            "left": parse_duration(d.get("duration"))}


def covers(decision_value: str, protected: str) -> bool:
    """Whether a decision's address or range and a protected address or network share any address. The server
    already filtered by this; the hub checks it again, so a reply that names something unrelated is not a ban on
    this address."""
    a, b = _net(decision_value), _net(protected)
    return a is not None and b is not None and a.version == b.version and a.overlaps(b)


# --- what to ask about -----------------------------------------------------------------------------------------------

GROUPS = ("self", "host", "never")


def _usable(ip) -> bool:
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


def _entry(out: dict, value: str, group: str, why: str, net: bool) -> None:
    e = out.get(value)
    if e is None:
        out[value] = {"value": value, "group": group, "net": net, "whys": [why], "bans": []}
        return
    if why not in e["whys"]:
        e["whys"].append(why)
    if GROUPS.index(group) < GROUPS.index(e["group"]):
        e["group"] = group


def protected(interfaces: dict | None, roles: dict[str, dict], hosts: list[tuple[str, str | None]],
              never: list[str], self_id: str) -> tuple[list[dict], list[str]]:
    """The addresses and networks DaemonSight asks CrowdSec about, merged by value:
    [{"value", "group", "net", "whys", "bans": []}], and the names of hosts whose address is not an IP.

    * `self`: the firewall's own addresses on internet-facing interfaces, and the networks of its trusted (LAN) and
      VPN interfaces (a ban on anything inside would cut it);
    * `host`: every host the hub knows, by its address (a collector's reported address, a remote system's address
      when it is an IP; a name is listed as not checked);
    * `never`: the owner's list.
    """
    out: dict[str, dict] = {}
    unresolved: list[str] = []
    for i in (interfaces or {}).get("interfaces", []):
        role = (roles.get(i.get("id") or "") or {}).get("role")
        label = i.get("name") or i.get("id") or i.get("device") or "interface"
        if role not in ("wan", "lan", "vpn"):
            continue
        for a in i.get("addresses", []):
            addr = str(a).split("%")[0].strip()
            net = _net(addr)
            if net is None:
                continue
            ip = ipaddress.ip_interface(addr).ip if "/" in addr else ipaddress.ip_address(addr)
            if not _usable(ip):
                continue
            if role == "wan" or net.prefixlen == net.max_prefixlen:
                _entry(out, str(ip), "self", f"this firewall's address on {label}", False)
            else:
                _entry(out, str(net), "self", f"this firewall's {'LAN' if role == 'lan' else 'VPN'} network {label}", True)
    for name, address in hosts:
        if name == self_id:
            continue
        text = (address or "").strip().strip("[]")
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            if text:
                unresolved.append(name)
            continue
        if _usable(ip):
            _entry(out, str(ip), "host", f"host {name}", False)
    for item in never:
        net = _net(item)
        if net is None:
            continue
        _entry(out, str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net), "never",
               "your never-ban list", net.prefixlen != net.max_prefixlen)
    order = {g: n for n, g in enumerate(GROUPS)}
    return sorted(out.values(), key=lambda e: (order[e["group"]], e["value"])), unresolved


def queries(entries: list[dict]) -> list[tuple[dict, dict]]:
    """[(entry, params)]: an address is one query (`ip=`); a network is two (`range=` containing it, and inside it).
    Capped at MAX_QUERIES; an entry that does not fit is left out and the caller says so."""
    out: list[tuple[dict, dict]] = []
    for e in entries:
        if e["net"]:
            wanted = [{"range": e["value"], "contains": "true", "limit": ROWS_PER_QUERY},
                      {"range": e["value"], "contains": "false", "limit": ROWS_PER_QUERY}]
        else:
            wanted = [{"ip": e["value"], "limit": ROWS_PER_QUERY}]
        if len(out) + len(wanted) > MAX_QUERIES:
            break
        out += [(e, p) for p in wanted]
    return out


# --- reading ---------------------------------------------------------------------------------------------------------

async def read(net, url: str, key: str, entries: list[dict], unresolved: list[str], now: float) -> dict:
    """Ask CrowdSec about every entry and about the local decisions, and build what is stored. Raises RemoteError when
    the Local API can't be reached or refuses the key. An address CrowdSec rejects is recorded on its entry."""
    asked = queries(entries)
    entries = [dict(e, bans=[]) for e in entries]
    by_value = {e["value"]: e for e in entries}
    sem = asyncio.Semaphore(PARALLEL)
    lapi = Lapi(url, key, net.lapi())

    async def one(entry, params):
        async with sem:
            return entry, await lapi.get(params)

    try:
        results = await asyncio.gather(*(one(e, p) for e, p in asked), return_exceptions=True)
        for r in results:
            if isinstance(r, RemoteError) and r.kind in ("auth", "tls", "unreachable"):
                raise r
        failed = [r for r in results if isinstance(r, Exception)]
        if failed and len(failed) == len(results):
            raise failed[0]
        for r in results:
            if isinstance(r, Exception):
                continue
            entry, rows = r
            target = by_value[entry["value"]]
            seen = {b["id"] for b in target["bans"] if b["id"] is not None}
            for row in rows:
                d = trim_decision(row)
                if d is None or not covers(d["value"], target["value"]) or (d["id"] is not None and d["id"] in seen):
                    continue
                if d["id"] is not None:
                    seen.add(d["id"])
                if len(target["bans"]) < BANS_KEPT:
                    target["bans"].append(d)
        local, local_error = None, None
        try:
            rows = await lapi.get({"origins": LOCAL_ORIGIN, "limit": LOCAL_ROWS})
            counts: dict[str, int] = {}
            for row in rows[:LOCAL_ROWS]:
                d = trim_decision(row)
                if d is not None and d["origin"] == LOCAL_ORIGIN:
                    counts[d["scenario"] or "(no scenario)"] = counts.get(d["scenario"] or "(no scenario)", 0) + 1
            top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            local = {"count": sum(counts.values()), "capped": len(rows) >= LOCAL_ROWS,
                     "scenarios": [{"scenario": s, "count": n} for s, n in top[:LOCAL_SCENARIOS_KEPT]]}
        except RemoteError as exc:
            if exc.kind in ("auth", "tls", "unreachable"):
                raise
            local_error = error_text(exc, key)
    finally:
        await lapi.aclose()
    errors = sum(1 for r in results if isinstance(r, Exception))
    return {"v": 1, "at": now, "endpoint": url, "entries": entries, "queries": len(asked) + 1,
            "skipped": len(entries) - len({e["value"] for e, _p in asked}),
            "errors": errors, "unresolved": unresolved, "local": local, "local_error": local_error, "fails": 0}


def failed(old: dict | None) -> dict:
    """What a failed read stores: the last good readings, with one more failure counted."""
    base = dict(old) if old else {}
    base["fails"] = int(base.get("fails") or 0) + 1
    return base


# --- findings --------------------------------------------------------------------------------------------------------

def steps(*lines: str) -> str:
    return "\n".join(lines)


ALLOWLIST_DOCS = "https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists"


def _howto(value: str) -> str:
    flag = "-r" if "/" in value else "-i"
    return steps(
        "Open a shell on the firewall (CrowdSec runs there) and run the fix below: it deletes the decision, and the "
        "firewall's bouncer stops blocking the address",
        f"Find out why it was banned. The scenario is in the finding. cscli alerts list {flag} {value}, then "
        "cscli alerts inspect <id> -d shows the events behind it",
        f"Stop it coming back with an allowlist: cscli allowlists create <name> -d \"addresses CrowdSec must not ban\" "
        f"(once), then cscli allowlists add <name> {value} -d \"why\". An allowlist stops new alerts for the address "
        f"but does not remove a decision that already exists, so run the fix as well ({ALLOWLIST_DOCS})",
        "This finding goes away at the next read, once the decision is gone")


HOWTO_UNREACHABLE = steps(
    "Check that CrowdSec runs on the firewall and listens where the hub looks: the bouncer's config there says "
    "api_url: http://<firewall address>:<port>/",
    "Open Hosts and Edit this system: check the CrowdSec address, and that the firewall lets the hub reach that port",
    "Check the key still exists: on the firewall, cscli bouncers list. If it does not, make a new one "
    "(cscli bouncers add daemonsight-hub) and enter it in the same form",
    "The finding goes away at the next good read")


def _fix(d: dict) -> str | None:
    """The command that ends one decision, or None when its value is not an address or a network (it comes from the
    firewall, so it is checked before it goes into a command to paste)."""
    value = d["value"]
    net = _net(value)
    if net is None or net.version not in (4, 6) or not re.fullmatch(r"[0-9A-Fa-f.:/]+", value):
        return None
    return f"cscli decisions delete {'-r' if '/' in value else '-i'} {shlex.quote(value)}"


def _since(left: float | None) -> str:
    if left is None:
        return ""
    h, m = divmod(int(left) // 60, 60)
    return f", {h} h {m} min left when read" if h else f", {m} min left when read"


def evaluate(data: dict | None, error: str | None = None) -> list[Finding]:
    """The `crowdsec.*` findings for what was last read. `error` is the last read's error, or None when it worked.
    A read that fails keeps the last good data (so a ban finding holds), and `fails` counts the failures in a row."""
    if not data:
        return []
    out: list[Finding] = []
    hits: dict[str, dict] = {}
    for e in data.get("entries", []):          # stored self first, then host, then never
        for b in e.get("bans", []):
            if b.get("type") != "ban" or not b.get("value"):
                continue
            h = hits.setdefault(b["value"], {"rule": "crowdsec.self_banned" if e["group"] == "self" else "crowdsec.host_banned",
                                             "ban": b, "covers": []})
            h["covers"].append(e)
    for value, h in sorted(hits.items()):
        b, covers_ = h["ban"], h["covers"]
        scen = b.get("scenario") or "an unnamed scenario"
        what = f"Scenario {scen}, origin {b.get('origin') or '?'}, {(b.get('type') or 'ban')} on {'a range' if '/' in value else 'one address'}{_since(b.get('left'))}."
        fix = _fix(b)
        basis = "ban:" + "|".join(sorted({b.get("scenario") or "", b.get("origin") or ""}))
        if h["rule"] == "crowdsec.self_banned":
            first = covers_[0]
            if not first["net"]:
                title = f"CrowdSec is banning this firewall's own address {value}" if value == first["value"] else \
                    f"CrowdSec is banning {value}, a range that includes this firewall's own address {first['value']}"
            else:
                inside = _net(value) is not None and _net(first["value"]) is not None and _net(value).subnet_of(_net(first["value"]))
                title = (f"CrowdSec is banning {value}, an address inside this firewall's network {first['value']}" if inside
                         else f"CrowdSec is banning {value}, a range that covers this firewall's network {first['value']}")
            detail = (f"{what} The firewall's CrowdSec bouncer drops every connection a banned address carries. "
                      "For the firewall's own address that is every connection it makes or translates for the network, "
                      "and a ban on the network or a host inside it cuts that part of the network off.")
        else:
            names = "; ".join(f"{c['value']} ({', '.join(c['whys'])})" for c in covers_[:5])
            title = f"CrowdSec is banning {value}, which covers an address DaemonSight protects"
            detail = (f"It covers {names}. {what} The firewall's CrowdSec bouncer drops every connection the banned "
                      "address carries. If this host's tunnel or service passes through this firewall, that link is cut.")
        out.append(Finding(h["rule"], value, "high", title, detail, LINK, fix, basis, _howto(value if fix else "<address>")))
    if (data.get("fails") or 0) >= UNREACHABLE_AFTER_FAILS:
        out.append(Finding("crowdsec.unreachable", "lapi", "low", "Can't read CrowdSec's Local API",
                           f"The hub could not read CrowdSec's Local API on the firewall for {data['fails']} reads in a row"
                           + (f": {error}" if error else "") + " Bans are not being watched until it can; the "
                           "findings above are from the last good read.", LINK, None, "lapi", HOWTO_UNREACHABLE))
    return out
