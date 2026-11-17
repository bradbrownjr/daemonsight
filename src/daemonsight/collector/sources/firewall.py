"""Inbound firewall summary from `nft -j list ruleset`.

Schema: libnftables-json(5). Output is {"nftables": [metainfo, table...,
chain..., rule..., set...]}; base chains carry type/hook/prio/policy; a rule's
"expr" is a list of statements such as
  {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}
  {"accept": null}, {"drop": null}, {"jump": {"target": "name"}}
Right-hand sides can be a number, {"set": [...]}, {"range": [lo, hi]}, or
"@name" for a named set.

This is a summary, not a packet simulator. For each base chain on the input
hook it works out the default verdict and which destination ports an accept
rule opens, following jumps and gotos. A rule with a match it doesn't
understand counts as conditional, so it never makes a port look more open than
it is. Not yet run against real output: unverified.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket

from . import Source, SourceUnavailable

ACCEPT, DROP = "accept", "drop"
# Matches that don't narrow who can reach a port.
NEUTRAL_META = {"nfproto", "l4proto", "protocol"}


def _ports(right, sets: dict) -> list[tuple[int, int]] | None:
    """Port ranges named by a match's right-hand side; None if unknown."""
    if isinstance(right, bool):
        return None
    if isinstance(right, int):
        return [(right, right)]
    if isinstance(right, str):
        if right.startswith("@"):
            return _ports({"set": sets.get(right[1:], [])}, sets) if right[1:] in sets else None
        if right.isdigit():
            return [(int(right), int(right))]
        try:
            p = socket.getservbyname(right)
            return [(p, p)]
        except OSError:
            return None
    if isinstance(right, dict):
        if "range" in right and isinstance(right["range"], list) and len(right["range"]) == 2:
            lo, hi = (_ports(x, sets) for x in right["range"])
            if lo and hi:
                return [(lo[0][0], hi[0][1])]
            return None
        if "set" in right:
            items = right["set"] if isinstance(right["set"], list) else [right["set"]]
            out = []
            for item in items:
                got = _ports(item, sets)
                if got is None:
                    return None
                out += got
            return out
    return None


def read_rule(expr: list, sets: dict) -> dict:
    """Classify one rule: its verdict, the ports it names, and its conditions."""
    rule = {"verdict": None, "target": None, "proto": None, "ports": None,
            "conditions": [], "established": False, "loopback": False}
    for st in expr or []:
        if not isinstance(st, dict) or not st:
            continue
        key = next(iter(st))
        val = st[key]
        if key in ("accept", "drop", "reject"):
            rule["verdict"] = ACCEPT if key == "accept" else DROP
        elif key in ("jump", "goto"):
            rule["verdict"] = key
            rule["target"] = (val or {}).get("target")
        elif key == "return":
            rule["verdict"] = "return"
        elif key in ("counter", "log", "limit", "comment", "mangle", "notrack"):
            continue
        elif key == "match":
            left, right, op = val.get("left") or {}, val.get("right"), val.get("op")
            if "payload" in left and left["payload"].get("field") == "dport":
                ports = _ports(right, sets) if op in ("==", "in") else None
                if ports is None:
                    rule["conditions"].append("dport " + json.dumps(right))
                else:
                    rule["proto"] = left["payload"].get("protocol")
                    rule["ports"] = ports
            elif "ct" in left and left["ct"].get("key") == "state":
                states = right if isinstance(right, list) else (right.get("set") if isinstance(right, dict) else [right])
                states = states if isinstance(states, list) else [states]
                if set(states) <= {"established", "related"}:
                    rule["established"] = True
                else:
                    rule["conditions"].append("ct state")
            elif "meta" in left and left["meta"].get("key") in ("iif", "iifname") and right == "lo":
                rule["loopback"] = True
            elif "meta" in left and left["meta"].get("key") in NEUTRAL_META:
                if left["meta"].get("key") == "l4proto" and right in ("tcp", "udp"):
                    rule["proto"] = rule["proto"] or right
                continue
            elif "meta" in left and left["meta"].get("key") in ("iif", "iifname"):
                rule["conditions"].append(f"iif {right}")
            elif "payload" in left and left["payload"].get("field") == "saddr":
                rule["conditions"].append(f"from {json.dumps(right)}")
            else:
                rule["conditions"].append(json.dumps(left)[:60])
        else:
            # xt matches from iptables-nft, sets updates, etc.
            rule["conditions"].append(key)
    return rule


def summarize(ruleset: dict) -> dict:
    items = ruleset.get("nftables", []) if isinstance(ruleset, dict) else []
    chains: dict[tuple, dict] = {}
    rules: dict[tuple, list] = {}
    sets: dict[str, list] = {}
    tables = []
    for it in items:
        if "table" in it:
            tables.append(f"{it['table'].get('family')} {it['table'].get('name')}")
        elif "chain" in it:
            c = it["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "set" in it:
            s = it["set"]
            elem = s.get("elem", [])
            sets[s.get("name")] = elem if isinstance(elem, list) else [elem]
        elif "rule" in it:
            r = it["rule"]
            rules.setdefault((r.get("family"), r.get("table"), r.get("chain")), []).append(r)

    def walk(key, seen) -> tuple[list[dict], bool, str | None]:
        """Open ports, whether everything is accepted, and the verdict that
        ends the chain unconditionally (None = it falls through)."""
        opened: list[dict] = []
        accept_all = False
        for r in rules.get(key, []):
            info = read_rule(r.get("expr"), sets)
            if info["established"] or info["loopback"]:
                continue  # replies and loopback don't open anything to new peers
            cond, verdict = info["conditions"], info["verdict"]
            unconditional = not cond and info["ports"] is None
            if verdict in ("jump", "goto") and info["target"]:
                sub = (key[0], key[1], info["target"])
                if sub in seen:
                    continue
                sub_open, sub_all, sub_end = walk(sub, seen | {sub})
                opened += [{**o, "conditions": cond + o["conditions"]} for o in sub_open]
                if sub_all and info["ports"]:
                    # "tcp dport 22 jump ssh" where ssh accepts: port 22 opens.
                    opened += [{"proto": info["proto"] or "th", "from": lo, "to": hi, "conditions": cond}
                               for lo, hi in info["ports"]]
                elif sub_all and not cond:
                    return opened, True, ACCEPT
                if unconditional and (verdict == "goto" or sub_end in (ACCEPT, DROP)):
                    return opened, accept_all, sub_end
                continue
            if verdict == ACCEPT:
                if info["ports"]:
                    opened += [{"proto": info["proto"] or "th", "from": lo, "to": hi, "conditions": cond}
                               for lo, hi in info["ports"]]
                elif not cond:
                    return opened, True, ACCEPT
            elif verdict == DROP and unconditional:
                return opened, accept_all, DROP
        return opened, accept_all, None

    inputs = []
    for key, c in chains.items():
        if c.get("hook") != "input" or c.get("type", "filter") != "filter":
            continue
        opened, accept_all, end = walk(key, {key})
        policy = c.get("policy", "accept")
        default = end or policy
        inputs.append({"family": key[0], "table": key[1], "chain": key[2], "prio": c.get("prio"),
                       "policy": policy, "default": DROP if default in (DROP, "reject") else ACCEPT,
                       "accept_all": accept_all, "open": opened})
    inputs.sort(key=lambda x: (x["prio"] if isinstance(x["prio"], int) else 0, x["family"], x["table"]))
    docker_nat = any(k[1] == "nat" and k[2] == "DOCKER" for k in chains)
    return {"tables": tables, "input": inputs, "docker_nat": docker_nat,
            "filtering": any(i["default"] == DROP for i in inputs)}


def port_verdict(fw: dict, proto: str, port: int, family: str = "ip") -> dict:
    """How the input chains treat new connections to proto/port.

    A packet must get through every input base chain of its family, so the
    strictest chain decides. Returns {"state": "open" | "restricted" |
    "blocked" | "unfiltered", "why": str}.
    """
    chains = [c for c in fw.get("input", []) if c["family"] in ("inet", family)]
    if not chains:
        return {"state": "unfiltered", "why": "No input chain"}
    results = []
    for c in chains:
        name = f"{c['family']} {c['table']} {c['chain']}"
        hits = [o for o in c["open"] if o["proto"] in (proto, "th") and o["from"] <= port <= o["to"]]
        if c["default"] == ACCEPT:
            results.append(("unfiltered", f"{name}: policy accept"))
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


class FirewallSource(Source):
    name = "firewall"

    def __init__(self, interval: int = 300, nft: str = "nft"):
        self.interval = interval
        self.nft = nft

    async def collect(self) -> dict:
        path = shutil.which(self.nft)
        if path is None:
            raise SourceUnavailable("nft is not installed")
        proc = await asyncio.create_subprocess_exec(
            path, "-j", "list", "ruleset",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        if proc.returncode != 0:
            msg = err.decode(errors="replace").strip() or f"nft exited {proc.returncode}"
            raise RuntimeError(msg)
        return summarize(json.loads(out or b"{}"))
