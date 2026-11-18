"""What the pages show for a system the hub reads from Unraid's API. Same
shapes as views.py (tables with data-label cells, row anchors that findings
link to, source panels naming the query), built from the `unraid_*` snapshots
the poller (remote/poll.py) stores."""

from __future__ import annotations

import time

from .. import db, findings as rules
from ..config import Config
from ..remote import store, unraid, unraid_rules
from . import provenance as prov
from . import views
from .views import _sortval, fmt_ago, fmt_bytes, fmt_duration, level_class, pct_class

PAGES = ("overview", "disks", "containers", "vms", "notifications")

STATE_BADGE = {"STARTED": "bg-green-lt", "RECON_DISK": "bg-yellow-lt"}
DISK_OK = "DISK_OK"
KIND_LABEL = {"parity": "Parity", "data": "Data", "cache": "Cache", "flash": "Boot flash", "boot": "Boot"}


def _data(snaps: dict, source: str) -> dict | None:
    s = snaps.get(source)
    return s.data if s and s.data and s.data.get("available") is not False else None


def _kb(v) -> str:
    return fmt_bytes(v * 1024) if v is not None else "—"


def _remote(conn, host: str):
    return store.get(conn, host)


def _panels(conn, cfg: Config) -> tuple[str | None, int]:
    r = _remote(conn, cfg.host_id)
    return (r["url"], r["interval"]) if r else (None, 60)


def _states(snaps: dict) -> dict:
    return {name: views._source_state(snaps, name) for name in unraid.SOURCES}


def _check_line(pc: dict | None, hist: list[dict]) -> tuple[str, str | None]:
    """A one-line parity check summary: (text, alert or None)."""
    pc = pc or {}
    if pc.get("running"):
        what = "paused" if pc.get("paused") else "running"
        return f"{what}, {pc.get('progress') or 0}% done", None
    done = [h for h in hist if h.get("status") == "COMPLETED" and h.get("date")]
    if not done:
        return "No completed check on record", None
    last = max(done, key=lambda h: h["date"])
    errs = int(last.get("errors") or 0)
    when = time.strftime("%Y-%m-%d", time.gmtime(last["date"]))
    return f"{when}, {errs} error{'s' if errs != 1 else ''}", (f"{errs} errors" if errs else None)


def overview(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    sysd, arr = _data(snaps, "unraid_system"), _data(snaps, "unraid_array")
    dk, vm = _data(snaps, "unraid_docker"), _data(snaps, "unraid_vms")
    ups, nt = _data(snaps, "unraid_ups"), _data(snaps, "unraid_notifications")
    hour_ago = time.time() - 3600

    tiles = None
    if sysd:
        mem, cpu = sysd["memory"], sysd["cpu"]
        used = (mem["total"] - mem["available"]) if mem.get("total") is not None and mem.get("available") is not None else None
        mpct = mem.get("percent")
        cap = (arr or {}).get("capacity") or {}
        tiles = {
            "cpu": {"percent": cpu.get("percent") or 0, "count": cpu.get("threads") or cpu.get("cores") or "?", "load": "",
                    "spark": views.sparkline(db.metric_series(conn, host, "cpu.percent", hour_ago))},
            "mem": {"percent": mpct or 0, "used": fmt_bytes(used), "total": fmt_bytes(mem.get("total")),
                    "pct": pct_class(mpct), "level": level_class(mpct)},
            "disk": None if cap.get("percent") is None else {
                "mount": "array", "percent": cap["percent"], "used": _kb(cap.get("used_kb")), "total": _kb(cap.get("total_kb")),
                "pct": pct_class(cap["percent"]), "level": level_class(cap["percent"], 80, 90), "others": 0},
            "net": None,
        }

    glance = []
    if sysd:
        note = " · ".join(x for x in (f"Kernel {sysd['kernel']}" if sysd.get("kernel") else "",
                                           f"API {sysd['api_version']}" if sysd.get("api_version") else "") if x)
        glance.append({"id": "os", "title": "Unraid", "value": sysd.get("version") or "?", "note": note or None})
        if sysd.get("boot_time"):
            glance.append({"title": "Uptime", "value": fmt_duration(time.time() - sysd["boot_time"]), "alert": None})
        cpu = sysd["cpu"]
        if cpu.get("brand"):
            glance.append({"title": "CPU", "value": cpu["brand"], "alert": None,
                           "note": f"{cpu.get('cores')} cores, {cpu.get('threads')} threads" if cpu.get("cores") else None})
    if arr:
        cap = arr["capacity"]
        started = arr["state"] == "STARTED"
        glance.append({"id": "array", "title": "Array", "value": arr["state"].replace("_", " ").capitalize(),
                       "alert": None if started else "not started", "link": "/disks#array",
                       "note": f"{_kb(cap.get('used_kb'))} of {_kb(cap.get('total_kb'))} used ({cap['percent']:.0f}%)"
                               if cap.get("percent") is not None else None})
        text, alert = _check_line(arr.get("parity_check"), arr.get("parity_history", []))
        if any(d["kind"] == "parity" for d in arr["disks"]):
            glance.append({"title": "Parity check", "value": text, "alert": alert, "link": "/disks#parity"})
    if dk:
        cs = dk["containers"]
        running = sum(1 for c in cs if c["state"] == "RUNNING")
        upd = sum(1 for c in cs if c.get("update"))
        glance.append({"title": "Containers", "value": f"{running} of {len(cs)} running", "alert": None,
                       "note": f"{upd} with an update" if upd else None, "link": "/containers"})
    if vm:
        vs = vm["vms"]
        glance.append({"title": "VMs", "value": f"{sum(1 for v in vs if v['state'] == 'RUNNING')} of {len(vs)} running",
                       "alert": None, "link": "/vms"})
    for i, d in enumerate((ups or {}).get("devices", [])):
        bits = [f"{d['charge']}% charge" if d.get("charge") is not None else "",
                f"{d['load']}% load" if d.get("load") is not None else ""]
        on_batt = "ONBATT" in unraid_rules._ups_state(d["status"])
        glance.append({"id": "ups" if i == 0 else None, "title": "UPS", "value": d["status"] or "unknown",
                       "alert": "on battery" if on_batt else None, "note": " · ".join(b for b in bits if b) or None})
    if nt:
        u = nt["unread"]
        glance.append({"title": "Unread notifications", "value": f"{u['alert']} alerts, {u['warning']} warnings",
                       "alert": None, "link": "/notifications", "note": f"{u['info']} info"})
    r = _remote(conn, host)
    if r:
        glance.append({"title": "Last read", "value": fmt_ago(r["last_poll"]) if r["last_poll"] else "never",
                       "alert": (r["last_error"] or "")[:120] if r["fails"] else None})

    open_f, accepted_f = views.findings_lists(conn, host)
    url, interval = _panels(conn, cfg)
    return {
        "host": views._host(cfg, snaps), "tiles": tiles, "findings": open_f, "accepted": accepted_f,
        "events": views.events_list(conn, host), "glance": glance,
        "sources": _states(snaps),
        "src": {"system": prov.unraid_section("unraid_system", url, interval), "findings": prov.section("findings", cfg),
                "events": prov.section("events", cfg)},
    }


def _temp_class(d: dict, thr: dict) -> str:
    t = d.get("temp")
    if t is None:
        return ""
    warn, crit = unraid_rules.temp_limits(d, thr)
    return "text-red" if t >= crit else "text-orange" if t >= warn else ""


def disks(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    arr, dk = _data(snaps, "unraid_array"), _data(snaps, "unraid_disks")
    models = unraid_rules._models(dk)
    url, interval = _panels(conn, cfg)
    rows = []
    for d in (arr or {}).get("disks", []):
        m = models.get(d["device"]) or {}
        bad = d["status"] not in (DISK_OK, "DISK_NP", "DISK_NEW")
        pct = d.get("percent")
        rows.append({
            "anchor": rules.anchor("disk", d["name"]), "name": d["name"], "device": d["device"],
            "model": " ".join(x for x in (m.get("vendor"), m.get("model")) if x) or "",
            "kind": KIND_LABEL.get(d["kind"], d["kind"]), "slot_v": _sortval(d.get("slot")),
            "status": d["status"].removeprefix("DISK_").replace("_", " ").lower() or "?",
            "status_badge": "bg-red text-red-fg" if bad else "bg-green-lt",
            "temp": f"{d['temp']:.0f} °C" if d.get("temp") is not None else ("spun down" if d.get("spinning") is False else "—"),
            "temp_v": _sortval(d.get("temp")), "temp_class": _temp_class(d, (arr or {}).get("thresholds") or {}),
            "size": _kb(d.get("size_kb")), "size_v": _sortval(d.get("size_kb")),
            "used": f"{pct:.0f}%" if pct is not None else "—", "used_v": _sortval(pct),
            "used_pct": pct_class(pct), "used_level": level_class(pct, 90, 95) if pct is not None else "bg-secondary",
            "used_detail": f"{_kb(d.get('fs_used_kb'))} of {_kb(d.get('fs_size_kb'))}" if pct is not None else "",
            "fs": d.get("fs_type") or "",
            "errors": int(d["errors"]) if d.get("errors") is not None else None, "errors_v": _sortval(d.get("errors")),
            "io": f"{d['reads']:,} / {d['writes']:,}" if d.get("reads") is not None and d.get("writes") is not None else "—",
            "smart": m.get("smart") or ("—" if not dk else "n/a"),
            "smart_bad": bool(m) and m.get("smart") != "OK" and m.get("interface") != "USB" and d["kind"] in ("parity", "data", "cache"),
            "spin": {True: "spinning", False: "standby"}.get(d.get("spinning"), "—"),
            "src": prov.unraid_disk(d, m.get("model")),
        })
    cap = (arr or {}).get("capacity") or {}
    history = []
    for h in (arr or {}).get("parity_history", [])[:8]:
        history.append({"date": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(h["date"])) if h.get("date") else "—",
                        "date_v": _sortval(h.get("date")), "status": (h["status"] or "?").lower(),
                        "errors": h.get("errors") if h.get("errors") is not None else "—",
                        "errors_bad": bool(h.get("errors")),
                        "duration": fmt_duration(h["duration"]) if h.get("duration") else "—",
                        "speed": h.get("speed") or "—"})
    pc_text, pc_alert = _check_line((arr or {}).get("parity_check"), (arr or {}).get("parity_history", []))
    return {
        "host": views._host(cfg, snaps),
        "array": None if not arr else {
            "state": arr["state"].replace("_", " ").capitalize(), "started": arr["state"] == "STARTED",
            "badge": STATE_BADGE.get(arr["state"], "bg-red text-red-fg"),
            "percent": cap.get("percent"), "pct": pct_class(cap.get("percent")),
            "level": level_class(cap.get("percent"), 90, 95) if cap.get("percent") is not None else "bg-secondary",
            "used": _kb(cap.get("used_kb")), "total": _kb(cap.get("total_kb")), "free": _kb(cap.get("free_kb")),
            "slots": f"{int(cap['disks_used'])} of {int(cap['disks_total'])} disk slots used" if cap.get("disks_total") else "",
            "check": pc_text, "check_alert": pc_alert, "has_parity": any(d["kind"] == "parity" for d in arr["disks"]),
            "thresholds": arr.get("thresholds") or {}},
        "rows": rows, "history": history, "smart_known": dk is not None,
        "array_state": views._source_state(snaps, "unraid_array"), "disks_state": views._source_state(snaps, "unraid_disks"),
        "src": {"array": prov.unraid_section("unraid_array", url, interval), "disks": prov.unraid_section("unraid_disks", url, interval)},
    }


def containers(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    dk = _data(snaps, "unraid_docker")
    url, interval = _panels(conn, cfg)
    rows = []
    for c in (dk or {}).get("containers", []):
        up = c.get("update")
        rows.append({
            "anchor": rules.anchor("ctr", c["name"]), "name": c["name"], "image": c["image"], "status": c["status"],
            "state": c["state"].lower(), "state_badge": "bg-green-lt" if c["state"] == "RUNNING" else "bg-secondary-lt",
            # Not "update": in a template c.update is the dict's update method.
            "update_text": "Available" if up else ("Current" if up is False else "Unknown"),
            "update_badge": "bg-azure-lt" if up else "bg-secondary-lt", "update_v": {True: 0, None: 1, False: 2}[up],
            "auto": "yes" if c["auto_start"] else "no", "orphaned": c.get("orphaned"),
            "ports": [{"text": f"{p['ip'] or '*'}:{int(p['public'])}→{int(p['private'])}/{(p['type'] or '').lower()}"}
                      for p in c.get("ports", []) if p.get("public") is not None and p.get("private") is not None],
            "src": prov.unraid_container(c),
        })
    return {"host": views._host(cfg, snaps), "rows": rows, "state": views._source_state(snaps, "unraid_docker"),
            "src": {"docker": prov.unraid_section("unraid_docker", url, interval)}}


def vms(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    vm = _data(snaps, "unraid_vms")
    url, interval = _panels(conn, cfg)
    rows = [{"anchor": rules.anchor("vm", v["name"]), "name": v["name"], "state": v["state"].lower(),
             "state_badge": {"RUNNING": "bg-green-lt", "CRASHED": "bg-red text-red-fg", "PAUSED": "bg-yellow-lt"}.get(
                 v["state"], "bg-secondary-lt")} for v in (vm or {}).get("vms", [])]
    snap = snaps.get("unraid_vms")
    unavailable = snap.data.get("reason") if snap and snap.data and snap.data.get("available") is False else None
    return {"host": views._host(cfg, snaps), "rows": rows, "state": views._source_state(snaps, "unraid_vms"),
            "unavailable": unavailable, "src": {"vms": prov.unraid_section("unraid_vms", url, interval)}}


def notifications(conn, cfg: Config) -> dict:
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    nt = _data(snaps, "unraid_notifications")
    url, interval = _panels(conn, cfg)
    rows = [{"anchor": rules.anchor("notif", i["id"][:60]), "title": i["title"] or "(no title)", "subject": i["subject"],
             "level": i["importance"].lower(), "level_badge": "bg-red text-red-fg" if i["importance"] == "ALERT" else "bg-yellow-lt",
             "when": fmt_ago(i["time"]) if i["time"] else "—", "when_v": _sortval(i["time"])}
            for i in (nt or {}).get("items", [])]
    return {"host": views._host(cfg, snaps), "rows": rows, "unread": (nt or {}).get("unread"),
            "state": views._source_state(snaps, "unraid_notifications"),
            "src": {"notifications": prov.unraid_section("unraid_notifications", url, interval)}}


PAGE_FUNCS = {"overview": overview, "disks": disks, "containers": containers, "vms": vms, "notifications": notifications}
