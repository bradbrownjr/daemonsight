"""fail2ban jails over the server's control socket.

Protocol, from fail2ban 1.1.0 (Debian 13) source:
  client/csocket.py   request = pickle.dumps(list of str) + b"<F2B_END_COMMAND>";
                      b"<F2B_CLOSE_COMMAND><F2B_END_COMMAND>" says goodbye
  server/asyncserver.py  reply = pickle.dumps(value) + b"<F2B_END_COMMAND>"
  server/transmitter.py  value is (0, result) on success, (1, exception) on error
  server/ipdns.py     IPAddr.__reduce__ pickles addresses as plain str

So every result is built from builtins. The unpickler below refuses anything
else, which keeps a hostile or broken peer from running code in the collector.

Commands used (all read-only): ping, version, status, status <jail>,
get <jail> logpath | journalmatch | bantime | findtime | maxretry | ignoreip |
actions | banip --with-time.
"""

from __future__ import annotations

import asyncio
import builtins
import io
import os
import pickle
import re

from . import Source, SourceUnavailable

END = b"<F2B_END_COMMAND>"
CLOSE = b"<F2B_CLOSE_COMMAND>"
# Protocol 4 is readable by every Python 3 that fail2ban supports.
PICKLE_PROTOCOL = 4
MAX_REPLY = 8 * 1024 * 1024
SAFE_BUILTINS = {"str", "int", "float", "bool", "list", "tuple", "dict", "set", "frozenset",
                 "bytes", "complex", "NoneType", "slice", "range"}
UNIT_IN_MATCH = re.compile(r"_SYSTEMD_UNIT=(\S+)")
FOREIGN_ERROR = re.compile(r"^[A-Za-z_]\w*(?:Exception|Error)$")


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins":
            if name in SAFE_BUILTINS:
                return getattr(builtins, name)
            obj = getattr(builtins, name, None)
            # Error replies carry an exception instance; building one runs no
            # foreign code.
            if isinstance(obj, type) and issubclass(obj, BaseException):
                return obj
        # fail2ban's own errors (fail2ban.exceptions.UnknownJailException and
        # the like) become a plain Exception subclass; nothing is imported.
        if module.split(".")[0] == "fail2ban" and FOREIGN_ERROR.match(name):
            return type(name, (Exception,), {})
        raise pickle.UnpicklingError(f"refused {module}.{name} from the fail2ban socket")


def safe_loads(data: bytes):
    return SafeUnpickler(io.BytesIO(data)).load()


class Fail2banError(Exception):
    pass


class Fail2banClient:
    def __init__(self, path: str, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout

    async def session(self, commands: list[list[str]]) -> list:
        """Send each command over one connection and return the results.

        A command fail2ban rejects comes back as a Fail2banError in its slot.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.path, limit=MAX_REPLY), self.timeout)
        except FileNotFoundError as exc:
            raise SourceUnavailable("fail2ban is not running (no control socket)") from exc
        except PermissionError as exc:
            raise PermissionError(f"Can't open {self.path}; the collector must run as root") from exc
        results = []
        try:
            for cmd in commands:
                writer.write(pickle.dumps([str(c) for c in cmd], PICKLE_PROTOCOL) + END)
                await writer.drain()
                raw = await asyncio.wait_for(reader.readuntil(END), self.timeout)
                reply = safe_loads(raw[: -len(END)])
                if isinstance(reply, (list, tuple)) and len(reply) == 2 and reply[0] in (0, 1):
                    code, value = reply
                    results.append(value if code == 0 else Fail2banError(f"{type(value).__name__}: {value}"))
                elif isinstance(reply, str) and reply.startswith("ERROR"):
                    results.append(Fail2banError(reply))
                else:
                    results.append(reply)
            writer.write(CLOSE + END)
            await writer.drain()
        except asyncio.LimitOverrunError as exc:
            raise Fail2banError("reply too large") from exc
        except asyncio.IncompleteReadError as exc:
            raise Fail2banError("fail2ban closed the connection mid-reply") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return results


def pairs(value) -> dict:
    """fail2ban status replies are lists of (label, value) pairs, nested."""
    out = {}
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
                v = item[1]
                out[item[0]] = pairs(v) if isinstance(v, (list, tuple)) and v and \
                    all(isinstance(x, (list, tuple)) and len(x) == 2 and isinstance(x[0], str) for x in v) else v
    return out


def parse_banip(lines) -> list[dict]:
    """Entries of `get <jail> banip --with-time`:
    '1.2.3.4 \\t2026-11-17 10:00:00 + 600 = 2026-11-17 10:10:00' (banmanager.py)."""
    out = []
    for line in lines or []:
        if not isinstance(line, str):
            continue
        ip, _, rest = line.partition(" \t")
        m = re.match(r"(.+?) \+ (-?\d+) = (.+)$", rest.strip())
        if m:
            out.append({"ip": ip.strip(), "banned_at": m.group(1), "seconds": int(m.group(2)),
                        "until": m.group(3)})
        else:
            out.append({"ip": ip.strip(), "banned_at": None, "seconds": None, "until": None})
    return out


def _ok(v, default=None):
    return default if isinstance(v, Exception) else v


def summarize_jail(name: str, status, logpath, journalmatch, bantime, findtime, maxretry,
                   ignoreip, actions, banip) -> dict:
    st = pairs(_ok(status, []))
    flt, act = st.get("Filter", {}), st.get("Actions", {})
    logs = [str(p) for p in _ok(logpath, []) or []]
    matches = [str(m) if isinstance(m, str) else " ".join(map(str, m)) for m in _ok(journalmatch, []) or []]
    units = sorted({u for m in matches for u in UNIT_IN_MATCH.findall(m)})
    return {
        "name": name,
        "backend": "systemd" if matches or (not logs and "Journal matches" in flt) else "file",
        "logpaths": [{"path": p, "exists": os.path.exists(p)} for p in logs],
        "journalmatch": matches,
        "units": units,
        "failed_now": flt.get("Currently failed"),
        "failed_total": flt.get("Total failed"),
        "banned_now": act.get("Currently banned"),
        "banned_total": act.get("Total banned"),
        "bans": parse_banip(_ok(banip, [])),
        "bantime": _ok(bantime),
        "findtime": _ok(findtime),
        "maxretry": _ok(maxretry),
        "ignoreip": [str(x) for x in _ok(ignoreip, []) or []],
        "actions": [str(x) for x in _ok(actions, []) or []],
    }


PER_JAIL = ["logpath", "journalmatch", "bantime", "findtime", "maxretry", "ignoreip", "actions"]


class Fail2banSource(Source):
    name = "fail2ban"

    def __init__(self, interval: int = 60, socket_path: str = "/var/run/fail2ban/fail2ban.sock"):
        self.interval = interval
        self.client = Fail2banClient(socket_path)

    async def collect(self) -> dict:
        version, status = await self.client.session([["version"], ["status"]])
        if isinstance(status, Exception):
            raise Fail2banError(str(status))
        names = [j.strip() for j in str(pairs(status).get("Jail list", "")).split(",") if j.strip()]
        jails = []
        for name in names:
            cmds = [["status", name]] + [["get", name, k] for k in PER_JAIL] + [["get", name, "banip", "--with-time"]]
            r = await self.client.session(cmds)
            jails.append(summarize_jail(name, *r))
        return {"version": _ok(version), "jails": jails}

    def metrics(self, data: dict) -> dict[str, float]:
        out = {}
        for j in data.get("jails", []):
            if isinstance(j.get("banned_now"), int):
                out[f"f2b.{j['name']}.banned"] = float(j["banned_now"])
        return out
