"""The per-host report: what to do, in order.

`build()` makes one structure from the database. The report page renders it
as HTML and `to_markdown()` renders it as text, so the two never disagree.

Every string that came from a host (titles, details, fixes, notes) is
untrusted. The page escapes it as templates always do; the Markdown escapes
it here.
"""

from __future__ import annotations

import re
import time

from .. import db, full_version
from .. import findings as rules
from ..config import Config
from . import views

# Severity groups, worst first. Critical goes with high: both mean "now".
GROUPS = (
    ("now", "Do now", ("critical", "high")),
    ("soon", "Do soon", ("medium",)),
    ("later", "When convenient", ("low", "info")),
)

# Pulled to the front of a merged step: refresh the lists, then upgrade.
FIRST = ("sudo apt update",)


def merge_commands(fixes: list[str]) -> str:
    """The commands of several fixes as one block: each line once, in order,
    with the package-list refresh first."""
    seen: list[str] = []
    for fix in fixes:
        for line in fix.split("\n"):
            line = line.rstrip()
            if line and line not in seen:
                seen.append(line)
    return "\n".join([x for x in seen if x in FIRST] + [x for x in seen if x not in FIRST])


def _is_kernel(item: dict) -> bool:
    return item["rule"] == "cve.package" and (
        item["key"] == "linux" or item["key"].startswith(("linux-signed", "linux-image")))


def steps(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Group open findings into step cards and the ones that are decisions.
    Returns (steps, decide). A finding with a fix goes into the card for its
    step; with a fix and no step, a card of its own; with no fix, it is a
    decision. Order: upgrade, restart, reboot, auto-updates, the cards of
    their own, then the operating system upgrade."""
    by_step: dict[str, list[dict]] = {}
    own: list[dict] = []
    decide: list[dict] = []
    for it in items:
        if not it["fix"]:
            decide.append(it)
        elif it["step"]:
            by_step.setdefault(it["step"], []).append(it)
        else:
            own.append(it)
    cards = []

    def card(key, title, members):
        return {"key": key, "title": title, "note": None, "findings": members,
                "commands": merge_commands([m["fix"] for m in members])}

    order = rules.STEP_ORDER
    first, last = order[:order.index("auto-updates") + 1], order[order.index("auto-updates") + 1:]
    for key in first:
        if key in by_step:
            cards.append(card(key, rules.STEP_TITLES[key], by_step[key]))
    for it in own:
        cards.append(card(it["id"], it["title"], [it]))
    for key in last:
        if key in by_step:
            cards.append(card(key, rules.STEP_TITLES[key], by_step[key]))
    for key, members in by_step.items():  # a step name this version doesn't know
        if key not in order:
            cards.append(card(key, key.replace("-", " ").capitalize(), members))
    # A kernel update needs a reboot after it. Say so when the host already asks for one.
    by_key = {c["key"]: c for c in cards}
    if "upgrade" in by_key and "reboot" in by_key and any(_is_kernel(m) for m in by_key["upgrade"]["findings"]):
        by_key["upgrade"]["note"] = "This includes a kernel update. Reboot afterwards (see Reboot)."
    return cards, decide


def _fmt_utc(ts: float | None) -> str:
    return views.fmt_when(ts) if ts else "never"


def build(conn, cfg: Config, base: str = "", now: float | None = None) -> dict:
    """Everything the report shows for one host. `base` is the URL prefix of
    the host's pages ("" on a single host, "/h/<host>" on a hub)."""
    now = time.time() if now is None else now
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    head = views._host(cfg, snaps)
    system = snaps.get("system")
    last_upload, version = (system.taken_at if system else None), full_version()
    if cfg.hub.enabled:
        row = conn.execute("SELECT last_seen, version FROM hosts WHERE id = ?", (host,)).fetchone()
        if row:
            last_upload, version = row["last_seen"], row["version"] or ""
    sup = head["support"]
    head.update({
        "role": "Workstation" if cfg.role == "workstation" else "Server",
        "support_text": sup["label"] if sup["label"] and not sup["plain"] else "",
        "last_upload": _fmt_utc(last_upload),
        "last_upload_label": ("Last read" if cfg.kind else "Last upload") if cfg.hub.enabled else "Last collected",
        "version": "" if cfg.kind else version,   # a system read over its API runs no DaemonSight
        "generated": _fmt_utc(now),
    })

    open_items, accepted = views.findings_lists(conn, host)
    for it in open_items + accepted:
        it["href"] = (base + it["link"]) if it["link"] else None
        it["step_title"] = rules.STEP_TITLES.get(it["step"]) if it["step"] else None
    cards, decide = steps(open_items)
    groups = [{"key": key, "title": title, "findings": [it for it in open_items if it["severity"] in sevs]}
              for key, title, sevs in GROUPS]
    rep = {"host": head, "base": base, "steps": cards, "decide": decide, "groups": groups,
           "accepted": accepted, "open": len(open_items), "markdown": ""}
    rep["markdown"] = to_markdown(rep)
    return rep


# --- Markdown ---------------------------------------------------------------

_INLINE = re.compile(r"([\\`*_{}\[\]()<>#+!|~&])")
_LEAD = re.compile(r"^(\d{1,9}[.)]|[-=])(\s|$)")


def md_text(value) -> str:
    """Text as one line of Markdown that shows exactly what it says. Every
    character with a meaning inline is escaped; whitespace, newlines included,
    collapses, so the text can't start a block of its own."""
    one = " ".join(str(value if value is not None else "").split())
    one = _INLINE.sub(r"\\\1", one)
    return "\\" + one if _LEAD.match(one) else one


def md_code(text: str) -> str:
    """A fenced block, long enough that the text can't close it."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}sh\n{text}\n{fence}"


def md_path(value: str) -> str:
    """A site path as inline code (a path may hold a backtick only if a host sent one)."""
    return "`" + value.replace("`", "'") + "`"


def _finding_md(it: dict, *, fix: bool, step: bool = False) -> list[str]:
    """A list item. Each part is its own paragraph inside it: single line
    breaks would join into one line."""
    out = [f"- **{md_text(it['label'])}**: {md_text(it['title'])}"]
    parts = []
    if it["detail"]:
        parts.append(md_text(it["detail"]))
    if it.get("howto"):
        parts.append("What to do:\n\n" + "\n".join(f"{n}. {md_text(step)}" for n, step in enumerate(it["howto"], 1)))
    if it["changed_note"]:
        parts.append(f"_{md_text(it['changed_note'])}_")
    if it.get("href"):
        parts.append(f"Where: {md_path(it['href'])}")
    if step and it.get("step_title"):
        parts.append(f"Step: {md_text(it['step_title'])}")
    for part in parts:
        out += ["", *("  " + ln if ln else "" for ln in part.split("\n"))]
    if fix and it["fix"]:
        out += ["", *("  " + ln for ln in md_code(it["fix"]).split("\n"))]
    out.append("")
    return out


def to_markdown(rep: dict) -> str:
    h = rep["host"]
    L = [f"# Report for {md_text(h['id'])}", ""]
    facts = [("Operating system", h["os"] or "unknown"), ("Support", h["support_text"]), ("Kernel", h["kernel"]), ("Up", h["uptime"]),
             ("Role", h["role"]), (h["last_upload_label"], h["last_upload"]), ("DaemonSight", h["version"]),
             ("Generated", h["generated"])]
    L += [f"- {label}: {md_text(v)}" for label, v in facts if v]
    L += ["", "## Steps", ""]
    if rep["steps"]:
        for n, c in enumerate(rep["steps"], 1):
            L += [f"### {n}. {md_text(c['title'])}", ""]
            if c["note"]:
                L += [md_text(c["note"]), ""]
            L += [md_code(c["commands"]), "", "Clears:"]
            for it in c["findings"]:
                tail = f" ({md_path(it['href'])})" if it.get("href") else ""
                L.append(f"- {md_text(it['title'])}{tail}")
            L.append("")
    else:
        L += ["No step has a command.", ""]
    L += ["## Decide", ""]
    if rep["decide"]:
        for it in rep["decide"]:
            L += _finding_md(it, fix=False)
    else:
        L += ["Nothing needs a decision.", ""]
    L += ["## All findings", ""]
    if rep["open"]:
        for g in rep["groups"]:
            if not g["findings"]:
                continue
            L += [f"### {md_text(g['title'])}", ""]
            for it in g["findings"]:
                L += _finding_md(it, fix=False, step=True)
    else:
        L += ["Nothing to report.", ""]
    L += ["## Accepted", ""]
    if rep["accepted"]:
        for it in rep["accepted"]:
            a = it["accepted"]
            L += [f"- {md_text(it['title'])}", "",
                  f"  Note: {md_text(a['note'])} ({md_text(a['by'])}, {md_text(a['when'])})", ""]
    else:
        L += ["Nothing accepted.", ""]
    return "\n".join(L).rstrip() + "\n"


def filename(host: str, now: float | None = None) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host) or "host"
    return f"{safe}-report-{time.strftime('%Y-%m-%d', time.gmtime(now if now is not None else time.time()))}.md"
