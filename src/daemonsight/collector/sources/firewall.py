"""Inbound firewall summary: input chains and port forwards.

Two readers feed one summary:

* `iptables-save` / `ip6tables-save` (iptables-save(8), iptables-extensions(8)).
  Text: "*table", ":CHAIN POLICY [packets:bytes]", "-A CHAIN <matches> -j
  TARGET", "COMMIT". Used whenever iptables is installed, for both backends:
  with the nf_tables backend the rules live in nf_tables, but nft only shows
  extension matches such as multiport as opaque "xt" expressions, so
  iptables-save is the readable view of them.
* `nft -j list ruleset` (libnftables-json(5)) for native nft tables. Tables
  that iptables-save already reported are skipped. The nft JSON reader has not
  been run against real output yet.

This is a summary, not a packet simulator. For each base chain on the input
hook it works out the default verdict and which destination ports an accept
rule opens, following jumps. A match it doesn't understand counts as a
condition, so a port never looks more open than the rules make it. DNAT rules
on the prerouting hook become "forwards": ports sent on to another host before
the input chain sees them.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import shutil
import socket
from collections import Counter

from . import Source, SourceUnavailable

ACCEPT, DROP = "accept", "drop"
ALL_PORTS = [(1, 65535)]
# nft meta keys that don't narrow who can reach a port.
NEUTRAL_META = {"nfproto", "l4proto", "protocol"}
# iptables -m modules whose options carry no restriction.
NEUTRAL_MODULES = {"tcp", "udp", "multiport", "comment", "state", "conntrack"}


def new_rule() -> dict:
    return {"verdict": None, "target": None, "proto": None, "ports": None, "conditions": [],
            "established": False, "loopback": False, "dnat_to": None}


def complement(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out, nxt = [], 1
    for lo, hi in sorted(ranges):
        if lo > nxt:
            out.append((nxt, lo - 1))
        nxt = max(nxt, hi + 1)
    if nxt <= 65535:
        out.append((nxt, 65535))
    return out


def ports_text(ranges: list[tuple[int, int]]) -> str:
    if ranges == ALL_PORTS:
        return "all ports"
    holes = complement(ranges)
    if len(holes) < len(ranges) and sum(h - l + 1 for l, h in ranges) > 1000:
        return "all except " + ",".join(str(l) if l == h else f"{l}-{h}" for l, h in holes)
    return ",".join(str(l) if l == h else f"{l}-{h}" for l, h in ranges)


# ---- nft JSON ---------------------------------------------------------------

def _nft_ports(right, sets: dict) -> list[tuple[int, int]] | None:
    """Port ranges named by a match's right-hand side; None if unknown."""
    if isinstance(right, bool):
        return None
    if isinstance(right, int):
        return [(right, right)]
    if isinstance(right, str):
        if right.startswith("@"):
            return _nft_ports({"set": sets[right[1:]]}, sets) if right[1:] in sets else None
        if right.isdigit():
            return [(int(right), int(right))]
        try:
            p = socket.getservbyname(right)
            return [(p, p)]
        except OSError:
            return None
    if isinstance(right, dict):
        if "range" in right and isinstance(right["range"], list) and len(right["range"]) == 2:
            lo, hi = (_nft_ports(x, sets) for x in right["range"])
            return [(lo[0][0], hi[0][1])] if lo and hi else None
        if "set" in right:
            items = right["set"] if isinstance(right["set"], list) else [right["set"]]
            out = []
            for item in items:
                got = _nft_ports(item, sets)
                if got is None:
                    return None
                out += got
            return out
    return None


def read_nft_rule(expr: list, sets: dict) -> dict:
    rule = new_rule()
    for st in expr or []:
        if not isinstance(st, dict) or not st:
            continue
        key = next(iter(st))
        val = st[key]
        if key in ("accept", "drop", "reject"):
            rule["verdict"] = ACCEPT if key == "accept" else DROP
        elif key in ("jump", "goto"):
            rule["verdict"], rule["target"] = key, (val or {}).get("target")
        elif key == "return":
            rule["verdict"] = "return"
        elif key == "dnat":
            rule["verdict"] = "dnat"
            addr, port = (val or {}).get("addr"), (val or {}).get("port")
            rule["dnat_to"] = f"{addr}:{port}" if port else str(addr)
        elif key in ("counter", "log", "limit", "comment", "mangle", "notrack"):
            continue
        elif key == "match":
            left, right, op = val.get("left") or {}, val.get("right"), val.get("op")
            if "payload" in left and left["payload"].get("field") == "dport":
                ports = _nft_ports(right, sets) if op in ("==", "in", "!=") else None
                if ports is None:
                    rule["conditions"].append("dport " + json.dumps(right))
                else:
                    rule["proto"] = left["payload"].get("protocol")
                    rule["ports"] = complement(ports) if op == "!=" else ports
            elif "ct" in left and left["ct"].get("key") == "state":
                states = right.get("set") if isinstance(right, dict) else right
                states = set(states if isinstance(states, list) else [states])
                if states <= {"established", "related"}:
                    rule["established"] = True
                elif "new" not in states:
                    rule["conditions"].append("ct state")
            elif "meta" in left and left["meta"].get("key") in ("iif", "iifname") and right == "lo":
                rule["loopback"] = True
            elif "meta" in left and left["meta"].get("key") in NEUTRAL_META:
                if left["meta"].get("key") == "l4proto" and right in ("tcp", "udp"):
                    rule["proto"] = rule["proto"] or right
            elif "meta" in left and left["meta"].get("key") in ("iif", "iifname"):
                rule["conditions"].append(f"in {right}")
            elif "payload" in left and left["payload"].get("field") == "saddr":
                rule["conditions"].append(f"from {json.dumps(right)}")
            else:
                rule["conditions"].append(json.dumps(left)[:60])
        else:
            rule["conditions"].append(key)  # xt matches, set updates, ...
    return rule


def parse_nft(ruleset: dict) -> dict:
    """{(family, table, chain): {"hook", "type", "policy", "prio"}} and rules."""
    chains, rules, sets, tables = {}, {}, {}, []
    seen = Counter()
    for it in ruleset.get("nftables", []) if isinstance(ruleset, dict) else []:
        if "table" in it:
            tables.append((it["table"].get("family"), it["table"].get("name")))
        elif "chain" in it:
            c = it["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = {
                "hook": c.get("hook"), "type": c.get("type"), "policy": c.get("policy", "accept"),
                "prio": c.get("prio")}
        elif "set" in it:
            s = it["set"]
            elem = s.get("elem", [])
            sets[s.get("name")] = elem if isinstance(elem, list) else [elem]
        elif "rule" in it:
            r = it["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            seen[(key, json.dumps(r.get("expr"), sort_keys=True))] += 1
            rules.setdefault(key, []).append(r)
    parsed = {k: [read_nft_rule(r.get("expr"), sets) for r in v] for k, v in rules.items()}
    return {"tables": tables, "chains": chains, "rules": parsed,
            "duplicates": sum(n - 1 for n in seen.values() if n > 1)}


# ---- iptables-save ----------------------------------------------------------

BUILTIN_HOOK = {"INPUT": "input", "PREROUTING": "prerouting", "FORWARD": "forward",
                "OUTPUT": "output", "POSTROUTING": "postrouting"}


def _ipt_ports(text: str) -> list[tuple[int, int]] | None:
    out = []
    for part in text.split(","):
        lo, _, hi = part.partition(":")
        try:
            a = int(lo) if lo else 1
            b = int(hi) if hi else (a if not _ else 65535)
        except ValueError:
            try:
                a = b = socket.getservbyname(lo)
            except OSError:
                return None
        out.append((a, b))
    return out


def read_ipt_rule(tokens: list[str]) -> dict:
    """One "-A CHAIN ..." line, already split, without the "-A CHAIN"."""
    rule = new_rule()
    i, neg = 0, False
    while i < len(tokens):
        t = tokens[i]
        val = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t == "!":
            neg = True
            i += 1
            continue
        step = 2
        if t in ("-p", "--protocol"):
            if neg:
                rule["conditions"].append(f"not {val}")
            else:
                rule["proto"] = val
        elif t in ("-s", "--source"):
            rule["conditions"].append(f"from {'not ' if neg else ''}{val}")
        elif t in ("-d", "--destination"):
            rule["conditions"].append(f"to {'not ' if neg else ''}{val}")
        elif t in ("-i", "--in-interface"):
            if val == "lo" and not neg:
                rule["loopback"] = True
            else:
                rule["conditions"].append(f"in {'not ' if neg else ''}{val}")
        elif t in ("-o", "--out-interface"):
            rule["conditions"].append(f"out {val}")
        elif t in ("--dport", "--dports", "--destination-port", "--destination-ports"):
            ports = _ipt_ports(val)
            if ports is None:
                rule["conditions"].append(f"dport {val}")
            else:
                rule["ports"] = complement(ports) if neg else ports
        elif t in ("--state", "--ctstate"):
            states = {s.upper() for s in val.split(",")}
            if states <= {"ESTABLISHED", "RELATED"} and not neg:
                rule["established"] = True
            elif "NEW" not in states or neg:
                rule["conditions"].append(f"state {val}")
        elif t == "-m":
            if val not in NEUTRAL_MODULES:
                rule["conditions"].append(f"-m {val}")
        elif t == "--comment":
            pass
        elif t in ("-j", "--jump", "-g", "--goto"):
            target = val
            if target == "ACCEPT":
                rule["verdict"] = ACCEPT
            elif target in ("DROP", "REJECT"):
                rule["verdict"] = DROP
            elif target == "RETURN":
                rule["verdict"] = "return"
            elif target == "DNAT":
                rule["verdict"] = "dnat"
            elif target in ("LOG", "MASQUERADE", "SNAT", "MARK", "CONNMARK", "NFLOG", "TCPMSS", "CT"):
                rule["verdict"] = None
            else:
                rule["verdict"], rule["target"] = ("goto" if t in ("-g", "--goto") else "jump"), target
        elif t == "--to-destination":
            rule["dnat_to"] = val
        elif t.startswith("-"):
            # Another extension option, such as --dst-type LOCAL: a condition.
            if val and not val.startswith("-") and val != "!":
                rule["conditions"].append(f"{t} {val}")
            else:
                rule["conditions"].append(t)
                step = 1
        else:
            step = 1
        neg = False
        i += step
    return rule


def parse_iptables_save(text: str, family: str) -> dict:
    """Chains and rules from iptables-save output; family is "ip" or "ip6"."""
    chains, rules, tables = {}, {}, []
    seen = Counter()
    odd: set[str] = set()
    table = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            tables.append((family, table))
        elif line == "COMMIT":
            table = None
        elif line.startswith(":") and table:
            name, policy = (line[1:].split() + ["-"])[:2]
            hook = BUILTIN_HOOK.get(name)
            chains[(family, table, name)] = {
                "hook": hook, "type": "nat" if table == "nat" else ("filter" if table == "filter" else table),
                "policy": policy.lower() if policy != "-" else None, "prio": 0}
        elif line.startswith("-A ") and table:
            try:
                tokens = shlex.split(line)
            except ValueError:
                tokens = line.split()
            key = (family, table, tokens[1])
            seen[(key, line)] += 1
            for flag, name in zip(tokens, tokens[1:]):
                if flag in ("-i", "-o", "--in-interface", "--out-interface") and "$" in name:
                    odd.add(name)
            rules.setdefault(key, []).append(read_ipt_rule(tokens[2:]))
    return {"tables": tables, "chains": chains, "rules": rules, "odd_names": sorted(odd),
            "duplicates": sum(n - 1 for n in seen.values() if n > 1)}


# ---- Summary ----------------------------------------------------------------

def _walk(key, rules: dict, seen: frozenset) -> tuple[list[dict], bool, str | None, list[dict]]:
    """Walk one chain: (open ports, accepts everything, unconditional end
    verdict or None, DNAT forwards)."""
    opened, forwards = [], []
    for info in rules.get(key, []):
        if info["established"] or info["loopback"]:
            continue  # replies and loopback don't open anything to new peers
        cond, verdict = info["conditions"], info["verdict"]
        unconditional = not cond and info["ports"] is None
        if verdict == "dnat":
            forwards.append({"proto": info["proto"] or "all", "ranges": info["ports"] or ALL_PORTS,
                             "to": info["dnat_to"], "conditions": cond})
            continue
        if verdict in ("jump", "goto") and info["target"]:
            sub = (key[0], key[1], info["target"])
            if sub in seen:
                continue
            s_open, s_all, s_end, s_fwd = _walk(sub, rules, seen | {sub})
            opened += [{**o, "conditions": cond + o["conditions"]} for o in s_open]
            forwards += [{**f, "conditions": cond + f["conditions"],
                          "ranges": info["ports"] or f["ranges"], "proto": info["proto"] or f["proto"]}
                         if info["ports"] and f["ranges"] == ALL_PORTS else
                         {**f, "conditions": cond + f["conditions"]} for f in s_fwd]
            if s_all and info["ports"]:
                opened += [{"proto": info["proto"] or "th", "from": lo, "to": hi, "conditions": cond}
                           for lo, hi in info["ports"]]
            elif s_all and not cond:
                return opened, True, ACCEPT, forwards
            if unconditional and (verdict == "goto" or s_end in (ACCEPT, DROP)):
                return opened, False, s_end, forwards
            continue
        if verdict == "return" and unconditional:
            return opened, False, None, forwards
        if verdict == ACCEPT:
            if info["ports"]:
                opened += [{"proto": info["proto"] or "th", "from": lo, "to": hi, "conditions": cond}
                           for lo, hi in info["ports"]]
            elif not cond:
                return opened, True, ACCEPT, forwards
        elif verdict == DROP and unconditional:
            return opened, False, DROP, forwards
    return opened, False, None, forwards


def summarize_parts(parts: list[dict], backend: str) -> dict:
    chains, rules, tables, dups, odd = {}, {}, [], 0, []
    for p in parts:
        odd += [n for n in p.get("odd_names", []) if n not in odd]
        chains.update(p["chains"])
        rules.update(p["rules"])
        tables += p["tables"]
        dups += p["duplicates"]
    inputs, forwards = [], []
    for key, c in chains.items():
        if c["hook"] == "input" and c["type"] == "filter":
            opened, accept_all, end, _ = _walk(key, rules, frozenset({key}))
            default = end or c["policy"] or ACCEPT
            inputs.append({"family": key[0], "table": key[1], "chain": key[2], "prio": c["prio"],
                           "policy": c["policy"], "default": DROP if default in (DROP, "reject") else ACCEPT,
                           "accept_all": accept_all, "open": [{**o, "conditions": list(o["conditions"])}
                                                              for o in opened]})
        elif c["hook"] == "prerouting" and c["type"] == "nat":
            for f in _walk(key, rules, frozenset({key}))[3]:
                forwards.append({**f, "family": key[0]})
    # The same forward added several times (a script re-run) is listed once.
    uniq: dict[str, dict] = {}
    for f in forwards:
        k = json.dumps([f["family"], f["proto"], f["ranges"], f["to"], f["conditions"]])
        if k in uniq:
            uniq[k]["copies"] += 1
        else:
            uniq[k] = {**f, "ranges": [list(r) for r in f["ranges"]], "copies": 1,
                       "ports": ports_text([tuple(r) for r in f["ranges"]])}
    inputs.sort(key=lambda x: (x["family"], x["prio"] if isinstance(x["prio"], int) else 0, x["table"]))
    return {
        "backend": backend,
        "tables": [f"{f} {t}" for f, t in tables],
        "input": inputs,
        "forwards": list(uniq.values()),
        "duplicates": dups,
        "odd_names": odd,
        "docker_nat": any(k[1] == "nat" and k[2] == "DOCKER" for k in chains),
        "filtering": any(i["default"] == DROP for i in inputs),
    }


def summarize(ruleset: dict) -> dict:
    """Summary from nft JSON alone (kept for callers and tests)."""
    return summarize_parts([parse_nft(ruleset)], "nft")


def port_verdict(fw: dict, proto: str, port: int, family: str = "ip") -> dict:
    """How new inbound connections to proto/port are handled.

    A forward on that port sends traffic elsewhere before the input chain.
    Otherwise every input base chain of the family must accept, so the
    strictest decides. Returns {"state": "forwarded" | "open" | "restricted" |
    "blocked" | "unfiltered", "why": str}.
    """
    for f in fw.get("forwards", []):
        if f["family"] in ("inet", family) and f["proto"] in (proto, "all") \
                and any(lo <= port <= hi for lo, hi in f["ranges"]):
            where = f" ({', '.join(f['conditions'])})" if f["conditions"] else ""
            return {"state": "forwarded", "why": f"DNAT to {f['to']}{where}"}
    chains = [c for c in fw.get("input", []) if c["family"] in ("inet", family)]
    if not chains:
        return {"state": "unfiltered", "why": "No input chain"}
    results = []
    for c in chains:
        name = f"{c['family']} {c['table']} {c['chain']}"
        hits = [o for o in c["open"] if o["proto"] in (proto, "th") and o["from"] <= port <= o["to"]]
        if c["default"] == ACCEPT:
            results.append(("unfiltered", f"{name}: default accept"))
        elif c["accept_all"] or any(not h["conditions"] for h in hits):
            results.append(("open", f"{name}: accepts {port}/{proto}"))
        elif hits:
            results.append(("restricted", f"{name}: accepts {port}/{proto} only with "
                            + ", ".join(hits[0]["conditions"])))
        else:
            results.append(("blocked", f"{name}: not accepted, default drop"))
    for wanted in ("blocked", "restricted", "open", "unfiltered"):
        for state, why in results:
            if state == wanted:
                return {"state": state, "why": why}
    return {"state": "unfiltered", "why": ""}


async def _run(*argv: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(err.decode(errors="replace").strip() or f"{argv[0]} exited {proc.returncode}")
    return out.decode(errors="replace")


class FirewallSource(Source):
    name = "firewall"

    def __init__(self, interval: int = 300, nft: str = "nft"):
        self.interval = interval
        self.nft = nft

    async def collect(self) -> dict:
        parts, backends = [], []
        covered: set[tuple[str, str]] = set()
        for tool, family in (("iptables-save", "ip"), ("ip6tables-save", "ip6")):
            path = shutil.which(tool)
            if path:
                part = parse_iptables_save(await _run(path), family)
                parts.append(part)
                covered.update(part["tables"])
                backends.append(tool)
        nft = shutil.which(self.nft)
        if nft:
            part = parse_nft(json.loads(await _run(nft, "-j", "list", "ruleset") or "{}"))
            # Tables iptables-save already read are iptables-nft's own.
            keep = {k for k in part["chains"] if (k[0], k[1]) not in covered}
            part["chains"] = {k: v for k, v in part["chains"].items() if k in keep}
            part["rules"] = {k: v for k, v in part["rules"].items() if k in keep}
            part["tables"] = [t for t in part["tables"] if t not in covered]
            parts.append(part)
            backends.append("nft")
        if not parts:
            raise SourceUnavailable("Neither nft nor iptables is installed")
        return summarize_parts(parts, " + ".join(backends))
