"""How urgent a CVE is, by CISA BOD 26-04 ("Prioritizing Security Updates Based on Risk", June 10, 2026).

Every update and CVE finding in DaemonSight (a host's packages, a container image, a firewall update) takes its severity
from this module, so they always agree. Four variables decide the urgency of one CVE on one system:

* Publicly Exposed: can the internet reach the system? Decided per system by cve/exposure.py.
* In the KEV: CISA's Known Exploited Vulnerabilities catalog (the `kev` table).
* Automatable by an adversary: CISA's SSVC decision point (can an attacker automate the whole attack), from CISA's ADP
  container of the CVE record (cve/records.py), else estimated from the EPSS probability.
* Technical Impact: SSVC's "total" (full control of the software or the data) or "partial", from the same place, else
  estimated as "partial".

Table 1 of the directive maps them to a timeline in calendar days. The table is DATA, not code: it lives in a bundled file,
data/priority/bod-26-04.json (format in docs/DESIGN.md, "Prioritisation"), so that a successor to the directive can be picked up
by replacing a file. `load` reads the bundled file, or `<data dir>/priority/override.json` when that one is valid; a file
that fails the strict check below is refused, the reason is logged and the bundled table is used. Nothing in a file is
executed or used as a template: it is parsed as JSON, checked and read as plain values.

Severity follows the timeline through the file's mapping: 3 days (with or without forensic triage) is critical, 14 high, 60
medium, "fix on system upgrade" low. CVSS is never an input: "CVSS scores such as 'critical' or 'high' do not prescribe
specific actions" (the implementation guidance), and FIRST's CVSS v4.0 user guide says a CVSS-B score "should not be used
alone to assess risk". It is shown for information only.

The directive binds federal agencies only. DaemonSight borrows its timelines as a published, risk-based default.
"""

from __future__ import annotations

import itertools
import json
import logging
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

log = logging.getLogger("daemonsight.priority")

BUNDLED = "bod-26-04.json"
OVERRIDE = Path("priority") / "override.json"
MAX_FILE_BYTES = 64 << 10
EPSS_URL = "https://www.first.org/epss/using-epss"
SSVC_URL = "https://github.com/cisagov/vulnrichment"

SEVERITIES = ("critical", "high", "medium", "low")
SEV_ORDER = SEVERITIES
INPUTS = {"exposed": ("yes", "no"), "kev": ("yes", "no"), "automatable": ("yes", "no"), "impact": ("total", "partial")}
TOP_KEYS = {"version", "directive", "inputs", "rows", "severity", "triage_steps"}
DIRECTIVE_KEYS = {"name", "title", "table_name", "url", "guidance_url", "table_url", "date"}
ROW_KEYS = {"row", "exposed", "kev", "automatable", "impact", "timeline", "days", "triage"}
UPGRADE = "upgrade"            # the severity map's key for "fix on system upgrade" (days null)
TOTAL, PARTIAL = "total", "partial"

# The vendor ratings that mean "not worth a security update on its own": Debian's urgency and Ubuntu's priority.
VENDOR_MINOR = ("unimportant", "negligible")
EST = "estimated by DaemonSight"


class TableError(ValueError):
    """A table file that is not acceptable."""


@dataclass(frozen=True)
class Row:
    row: int
    days: int | None            # the timeline in calendar days (None: fix on system upgrade)
    triage: bool                # the row also asks for forensic triage
    timeline: str               # the table's wording, "3 days and forensic triage"


@dataclass(frozen=True)
class Table:
    version: int
    name: str                   # "CISA BOD 26-04": how findings and panels name the directive
    title: str
    table_name: str             # "Table 1": what the directive calls the table
    url: str
    guidance_url: str
    table_url: str
    date: str
    rows: dict                  # (exposed, kev, automatable, impact) -> Row
    severity: dict              # days (int) or None -> severity
    triage_steps: tuple
    source: str = "bundled"     # "bundled", or the override file's path

    def lookup(self, exposed: bool, kev: bool, automatable: bool, impact: str) -> Row:
        return self.rows[(exposed, kev, automatable, impact)]


# --- loading and checking -----------------------------------------------------------------------------------------------

def _text(v, what: str, limit: int = 600) -> str:
    if not isinstance(v, str) or not v.strip() or len(v) > limit or any(ord(c) < 32 for c in v):
        raise TableError(f"{what} must be a short text")
    return v


def _url(v, what: str) -> str:
    v = _text(v, what, 400)
    if not re.fullmatch(r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", v):
        raise TableError(f"{what} must be an https address")
    return v


def _keys(d, want: set, what: str) -> None:
    if not isinstance(d, dict):
        raise TableError(f"{what} must be an object")
    if set(d) != want:
        extra, missing = sorted(set(d) - want), sorted(want - set(d))
        raise TableError(f"{what} has " + "; ".join(x for x in (f"unknown keys {extra}" if extra else "", f"missing keys {missing}" if missing else "") if x))


def _int(v, what: str, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise TableError(f"{what} must be a whole number from {lo} to {hi}")
    return v


def parse(doc, source: str = "bundled") -> Table:
    """A `Table` from a decoded JSON document, or TableError naming the first thing wrong. Strict: exactly the keys of the
    format, the types, every combination of the four inputs once, a severity for every timeline, severities from the allowed
    set."""
    _keys(doc, TOP_KEYS, "the file")
    version = _int(doc["version"], "version", 1, 10 ** 6)
    d = doc["directive"]
    _keys(d, DIRECTIVE_KEYS, "directive")
    name, title = _text(d["name"], "directive.name", 60), _text(d["title"], "directive.title", 200)
    table_name = _text(d["table_name"], "directive.table_name", 60)
    urls = {k: _url(d[k], f"directive.{k}") for k in ("url", "guidance_url", "table_url")}
    date = _text(d["date"], "directive.date", 10)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise TableError("directive.date must be YYYY-MM-DD")
    _keys(doc["inputs"], set(INPUTS), "inputs")
    for k, allowed in INPUTS.items():
        v = doc["inputs"][k]
        if not isinstance(v, list) or sorted(v, key=str) != sorted(allowed):
            raise TableError(f"inputs.{k} must list exactly {list(allowed)}")
    rows_in = doc["rows"]
    if not isinstance(rows_in, list) or len(rows_in) != 16:
        raise TableError("rows must be a list of 16 rows")
    rows: dict = {}
    numbers: set[int] = set()
    day_keys: set[str] = set()
    for i, r in enumerate(rows_in, 1):
        _keys(r, ROW_KEYS, f"row {i}")
        n = _int(r["row"], f"row {i} number", 1, 16)
        if n in numbers:
            raise TableError(f"row number {n} appears twice")
        numbers.add(n)
        vals = {}
        for k, allowed in INPUTS.items():
            if r[k] not in allowed:
                raise TableError(f"row {n}: {k} must be one of {list(allowed)}")
            vals[k] = r[k]
        days = r["days"]
        if days is not None:
            days = _int(days, f"row {n} days", 1, 3650)
        if not isinstance(r["triage"], bool):
            raise TableError(f"row {n}: triage must be true or false")
        key = (vals["exposed"] == "yes", vals["kev"] == "yes", vals["automatable"] == "yes", vals["impact"])
        if key in rows:
            raise TableError(f"row {n} repeats the inputs of another row")
        rows[key] = Row(n, days, r["triage"], _text(r["timeline"], f"row {n} timeline", 80))
        day_keys.add(UPGRADE if days is None else str(days))
    for combo in itertools.product((True, False), (True, False), (True, False), ("total", "partial")):
        if combo not in rows:
            raise TableError(f"no row for {combo}")
    sev_in = doc["severity"]
    if not isinstance(sev_in, dict):
        raise TableError("severity must be an object")
    for k, v in sev_in.items():
        if not (k == UPGRADE or (k.isdigit() and str(int(k)) == k and int(k) > 0)):
            raise TableError(f"severity key {k!r} must be a number of days or \"{UPGRADE}\"")
        if v not in SEVERITIES:
            raise TableError(f"severity {v!r} for {k!r} is not one of {list(SEVERITIES)}")
    if set(sev_in) != day_keys:
        raise TableError(f"severity must map exactly the timelines the rows use: {sorted(day_keys)}")
    severity = {None if k == UPGRADE else int(k): v for k, v in sev_in.items()}
    steps = doc["triage_steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 10:
        raise TableError("triage_steps must be a list of 1 to 10 texts")
    steps = tuple(_text(s, "a triage step", 300) for s in steps)
    return Table(version, name, title, table_name, urls["url"], urls["guidance_url"], urls["table_url"], date, rows, severity, steps, source)


def _bundled() -> Table:
    text = resources.files("daemonsight.data").joinpath("priority", BUNDLED).read_text(encoding="utf-8")
    return parse(json.loads(text), "bundled")


def _read(path: Path) -> Table:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise TableError(f"the file is larger than {MAX_FILE_BYTES >> 10} KB")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise TableError(f"cannot read it: {type(exc).__name__}") from None
    except ValueError as exc:
        raise TableError(f"not valid JSON: {str(exc)[:80]}") from None
    return parse(doc, str(path))


_bundled_table: Table | None = None
_cache: dict = {}
_current: Table | None = None


def bundled() -> Table:
    global _bundled_table
    if _bundled_table is None:
        _bundled_table = _bundled()
    return _bundled_table


def load(data_dir: str | Path | None = None) -> Table:
    """The table in force: `<data_dir>/priority/override.json` when it exists and is valid, else the bundled
    data/priority/bod-26-04.json. An override that is not valid is refused: the reason is logged (once for each version of
    the file) and the bundled table is used. Cached by the override's modification time, so calling it on every pass is cheap."""
    path = Path(data_dir) / OVERRIDE if data_dir else None
    sig = None
    if path is not None:
        try:
            st = path.stat()
            sig = (str(path), st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
    if sig is None:
        return bundled()
    if sig in _cache:
        return _cache[sig]
    try:
        table = _read(path)
    except TableError as exc:
        log.warning("Ignoring %s: %s. Using the bundled %s table.", path, exc, BUNDLED)
        table = bundled()
    _cache.clear()
    _cache[sig] = table
    return table


def use(data_dir: str | Path | None) -> Table:
    """Make the table for `data_dir` the one `rate` and the text helpers use by default. Called at the places that hold a Config
    (the CVE chore, the remote poller, the pages)."""
    global _current
    _current = load(data_dir)
    return _current


def current() -> Table:
    return _current if _current is not None else load(None)


# --- rating -------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Rating:
    """The urgency of one CVE on one system."""
    row: int                    # the table row, 1 to 16
    days: int | None            # the timeline (None: fix on system upgrade)
    triage: bool                # the row also asks for forensic triage
    severity: str
    exposed: bool
    kev: bool
    automatable: bool
    impact: str                 # "total" or "partial"
    auto_estimated: bool = False    # Automatable was not rated by CISA: estimated from EPSS
    impact_estimated: bool = False  # Technical Impact was not rated by CISA: assumed partial
    vendor_lowered: bool = False    # the vendor's rating moved it to low (see `rate`)
    directive: str = "CISA BOD 26-04"   # the directive's name, from the table's file
    table_name: str = "Table 1"     # what the directive calls its table
    timeline: str = ""              # the row's wording

    @property
    def deadline(self) -> str:
        return deadline_text(self.days, self.directive)

    @property
    def short(self) -> str:
        return timeline_text(self.days)

    @property
    def estimated(self) -> bool:
        return self.auto_estimated or self.impact_estimated

    @property
    def order(self) -> tuple:
        """Smaller is more urgent: the timeline, then forensic triage first, then the table row."""
        return (self.days if self.days is not None else 10 ** 6, not self.triage, self.row)


def timeline_text(days: int | None) -> str:
    """"3 days", "14 days" or "Next upgrade": the short form for a table column."""
    return "Next upgrade" if days is None else f"{days} days"


def deadline_text(days: int | None, directive: str | None = None) -> str:
    """The sentence a finding states: "Fix within 3 days (CISA BOD 26-04 timeline)" or "Fix at the next upgrade"."""
    if days is None:
        return "Fix at the next upgrade"
    return f"Fix within {days} days ({directive or current().name} timeline)"


def vendor_minor(urgency: str | None) -> bool:
    return (urgency or "").strip().lower() in VENDOR_MINOR


def rate(cve: dict, exposed: bool, epss_automatable: float, table: Table | None = None) -> Rating:
    """The table row, timeline and severity of one CVE on a system. `cve` is a dict from `match.host_cves`: "kev" (bool),
    "epss" (probability or None), "automatable" ("yes"/"no"/None) and "impact" ("total"/"partial"/None) from CISA's SSVC rating,
    "urgency" (Debian's urgency or Ubuntu's priority).

    Without CISA's rating: Automatable is "yes" when the EPSS probability is at or above `epss_automatable` (FIRST: the "EPSS
    equivalent effort level" of patching every CVSS Critical is "approximately the 90th percentile (>=0.04)"), else "no";
    Technical Impact is "partial". Both are marked as estimated.

    The vendor rule: a CVE the vendor rates unimportant (Debian) or negligible (Ubuntu) is low, a fix at the next upgrade,
    only when the system is not exposed and the CVE is not in the KEV catalog. The row it would have had stays in the
    rating."""
    t = table or current()
    kev = bool(cve.get("kev"))
    auto = cve.get("automatable")
    auto_est = auto not in ("yes", "no")
    automatable = (cve.get("epss") or 0) >= epss_automatable if auto_est else auto == "yes"
    impact = cve.get("impact")
    impact_est = impact not in (TOTAL, PARTIAL)
    if impact_est:
        impact = PARTIAL
    row = t.lookup(bool(exposed), kev, automatable, impact)
    days, triage = row.days, row.triage
    lowered = vendor_minor(cve.get("urgency")) and not exposed and not kev
    if lowered:
        days, triage = None, False
    return Rating(row.row, days, triage, t.severity[days], bool(exposed), kev, automatable, impact, auto_est, impact_est,
                  lowered, t.name, t.table_name, row.timeline)


def worst(ratings) -> Rating | None:
    """The most urgent of several ratings: an update takes the worst CVE it fixes."""
    best = None
    for r in ratings:
        if best is None or r.order < best.order:
            best = r
    return best


def worse_severity(a: str | None, b: str | None) -> str | None:
    """The more severe of two severities (None counts as none)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if SEV_ORDER.index(a) <= SEV_ORDER.index(b) else b


def attach(cves: list[dict], exposed: bool, epss_automatable: float, table: Table | None = None) -> list[dict]:
    """Rate each CVE dict and add "rating" to it, then sort them most urgent first, then by EPSS, then the id. Returns the
    same list sorted."""
    t = table or current()
    for c in cves:
        c["rating"] = rate(c, exposed, epss_automatable, t)
    cves.sort(key=sort_key)
    return cves


def sort_key(c: dict):
    """Most urgent first (the table's timeline), then the higher EPSS probability, then a fix over none, then the CVE id."""
    return (c["rating"].order, -(c.get("epss") or 0), {"fix": 0, "esm": 1}.get(c.get("state"), 2), c["cve"])


# --- text ----------------------------------------------------------------------------------------------------------------

def epss_text(prob: float | None, pctile: float | None) -> str:
    """"15.3% (92nd)": FIRST says to use the probability and show the percentile beside it
    (https://www.first.org/epss/articles/prob_percentile_bins)."""
    if prob is None:
        return "no EPSS score"
    p = prob * 100
    head = f"{p:.1f}%" if p >= 0.1 or p == 0 else "under 0.1%"
    if pctile is None:
        return head
    n = min(max(int(round(pctile * 100)), 0), 100)
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{head} ({n}{suffix})"


def inputs_text(r: Rating, exposure_why: str | None = None) -> list[str]:
    """The four inputs and their values, one line each, for the (i) panel and a finding's steps. Estimates are marked."""
    why = f": {exposure_why}" if exposure_why else ""
    return [
        f"Publicly exposed: {'yes' if r.exposed else 'no'}{why}",
        f"In CISA's KEV catalog: {'yes' if r.kev else 'no'}",
        f"Automatable by an adversary: {'yes' if r.automatable else 'no'} ({EST}, from the EPSS probability)" if r.auto_estimated
        else f"Automatable by an adversary: {'yes' if r.automatable else 'no'} (CISA)",
        f"Technical impact: {r.impact} ({EST}: CISA has not rated this CVE)" if r.impact_estimated
        else f"Technical impact: {r.impact} (CISA)",
    ]


def basis_text(r: Rating) -> str:
    """"CISA BOD 26-04 Table 1 row 4: 14 days" for a finding's detail (names from the table's file)."""
    extra = ", lowered by the vendor's rating to fix on system upgrade" if r.vendor_lowered else ""
    return f"{r.directive} {r.table_name} row {r.row}: {r.timeline}{extra}"
