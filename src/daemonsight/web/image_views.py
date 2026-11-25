"""The Container images page, for both kinds of system that have one: an Unraid system (package lists from its Docker reader) and a
host with a collector (package lists the collector sends). The cells and the coverage lines are the same; the pages differ only
in where the lists come from and what to do about a missing one. See docs/DESIGN.md, "Docker reader" and "Collector hosts: image
CVEs"."""

from __future__ import annotations

from ..cve import priority
from . import views
from .views import fmt_ago

CVES_SHOWN = 30


def image_findings(conn, host: str) -> dict[tuple[str, str], dict]:
    active, held = views.findings_lists(conn, host)
    return {(f["rule"], f["key"]): f for f in active + held if f["rule"] in ("docker.eol_base", "docker.image_cves")}


def cve_cell(r: dict) -> dict:
    """The "Fixable CVEs" cell of one image: {"text", "kev", "top", "note", "v"}."""
    kind, c = r["kind"], r["cve"]
    if kind in ("debian", "alpine", "ubuntu") and c and c["state"] == "matched":
        n = len(c["fixable"])
        top = c["fixable"][0] if c["fixable"] else None
        from ..cve import match
        # Alpine's secdb has no count of CVEs without a fix; Ubuntu's data has fixes that exist only in Ubuntu Pro's ESM archives
        bits = ([f"{c['unfixed']} with no fix yet"] if c["unfixed"] else []) + (
            [f"{len(c['esm'])} fixed only in Ubuntu Pro (ESM)"] if c.get("esm") else [])
        note = ", ".join(bits) or None
        why = c["exposure"].why
        base = {"ubuntu": views.UBUNTU_TRACKER, "debian": views.TRACKER}.get(kind, views.NVD)
        rows = [{"cve": x["cve"], "url": base + x["cve"], "kev": x["kev"], "fix": views.fix_cell(x, why),
                 "epss_text": priority.epss_text(x["epss"], x.get("pctile")) if x["epss"] is not None else "—",
                 "cvss": views.cvss_text(x), "fixed": x.get("fixed") or ""} for x in c["fixable"][:CVES_SHOWN]]
        return {"text": f"{n} fixable" if n else "None fixable", "kev": len(c["kev"]),
                "top": priority.epss_text(top["epss"], top.get("pctile")) if top and top["epss"] is not None else None,
                "note": note or c.get("note") or None, "v": n,
                "fix": views.fix_cell(c["worst"], why) if c["worst"] else None,
                "exposure": {"label": c["exposure"].label, "why": why}, "rows": rows, "more": max(0, n - CVES_SHOWN)}
    if kind == "alpine" and c and c["state"] == "absent":
        return {"text": f"{c['label']}: not in Alpine's security database", "v": -1}
    if kind == "ubuntu" and c and c["state"] == "absent":
        return {"text": f"{c['label']}: not in Canonical's OVAL data", "v": -1}
    if kind == "alpine" and c and c["state"] == "unmapped":
        return {"text": "Release not named (edge?): not matched", "v": -1}
    if kind in ("debian", "alpine", "ubuntu"):
        return {"text": "CVE matching is off" if c and c["state"] == "off" else "Waiting for the CVE matcher", "v": -1}
    if kind == "other" and r["manager"]:
        return {"text": "Not matched for this OS", "v": -1}
    return {"text": "—", "v": -1}


def packages_cell(r: dict) -> dict:
    if r["state"] == "read":
        return {"text": f"{r['count']} read", "note": r["manager"], "v": r["count"]}
    reasons = {"stopped": "Not read: stopped", "waiting": "Waiting for its first read"}
    err = r["error"] or "not read"
    return {"text": reasons.get(r["state"]) or err[:1].upper() + err[1:], "note": None, "v": -1}


def ubuntu_lines(cves: dict | None, now: float) -> list[dict]:
    """One line per Ubuntu release the system's images run, for the coverage card: how Canonical's OVAL data stands for it,
    and the last failed download's reason when there was one ({"text", "error"})."""
    from ..cve import ubuntu
    out = []
    for rel, st in sorted(((cves or {}).get("ubuntu") or {}).items()):
        name = ubuntu.display(rel)
        if st["state"] == "absent":
            text = f"{name}: not in Canonical's OVAL data, so nothing is matched for it"
        elif st["state"] == "ok":
            text = f"{name}: OVAL data checked {fmt_ago(st['ok_at'], now)}"
        else:
            text = f"{name}: OVAL data not downloaded yet"
        err = None
        if st["error"]:
            err = (f"The last download failed ({st['error']}); "
                   + ("the copy from the earlier download is used" if st["state"] == "ok" else "there is no copy yet"))
        out.append({"text": text, "error": err})
    return out


def alpine_lines(cves: dict | None, now: float) -> list[dict]:
    """One line per Alpine release the system's images run, for the coverage card: how secdb stands for it, and the last
    failed download's reason when there was one ({"text", "error"})."""
    from ..cve import alpine
    out = []
    for rel, st in sorted(((cves or {}).get("alpine") or {}).items()):
        name = alpine.display(rel)
        if st["state"] == "absent":
            text = f"{name}: not in Alpine's security database, so nothing is matched for it"
        elif st["state"] == "ok":
            text = f"{name}: secdb data checked {fmt_ago(st['ok_at'], now)}"
        else:
            text = f"{name}: secdb data not downloaded yet"
        err = None
        if st["error"]:
            err = (f"The last download failed ({st['error']}); "
                   + ("the copy from the earlier download is used" if st["state"] == "ok" else "there is no copy yet"))
        out.append({"text": text, "error": err})
    return out


def distro_badge(status: str) -> str:
    from .. import distro
    return distro.STATUS_BADGE.get(status, "bg-secondary-lt")


def image_rows(a: dict | None, found: dict, collector: bool = False) -> list[dict]:
    """The rows of the Images in use table from `docker_images.analyze`: each with its status (the worse of its image_cves finding and,
    for an end-of-life base, the eol_base one), cells, and source panel."""
    from . import provenance as prov
    rows = []
    for r in (a or {}).get("rows", []):
        cands = []
        if ("docker.image_cves", r["name"]) in found:
            cands.append(found[("docker.image_cves", r["name"])])
        if r["support"]["status"] in ("eol", "ended") and ("docker.eol_base", "all") in found:
            cands.append(found[("docker.eol_base", "all")])
        sts = [(views.status_of(False, f), f) for f in cands]
        st, f = next(((s, f) for s, f in sts if s["attention"]), sts[0] if sts else (None, None))
        sup = r["support"]
        rows.append({**r, "status": st, "pk": packages_cell(r), "cvec": cve_cell(r),
                     "sup_badge": distro_badge(sup["status"]), "sup_v": sup["eol"] or "",
                     "containers_text": ", ".join(r["containers"][:3]) + (f" and {len(r['containers']) - 3} more" if len(r["containers"]) > 3 else ""),
                     "src": {**prov.docker_image_row(r, collector), "finding": f, "anchor": r["anchor"]}})
    return rows


def coverage(rows: list[dict], a: dict | None, cves: dict | None, now: float) -> dict:
    """What both pages' summary line and "What is checked" card use."""
    return {"rows": rows, "counts": (a or {}).get("counts") or {}, "eol": len((a or {}).get("eol", [])),
            "fixable": sum(1 for r in rows if r["cvec"]["v"] > 0), "kev": sum(1 for r in rows if r["cvec"].get("kev")),
            "cve_off": bool(cves) and not cves["enabled"], "cve_missing": bool(cves) and cves["enabled"] and not cves["available"],
            "feed_ago": fmt_ago(cves["feed_at"], now) if cves and cves.get("feed_at") else None,
            "alpine_lines": alpine_lines(cves, now), "ubuntu_lines": ubuntu_lines(cves, now)}


OLD_COLLECTOR = ("This host's collector has not sent image package lists. Update DaemonSight on the host to the version this hub runs "
                 "(Hosts, Update), and make sure [collector] docker_read_packages is not false in its config. Until then these "
                 "images are not read, which is not the same as having no CVEs.")


def host_images(conn, cfg) -> dict:
    """The Container images page of a host with a collector: each image a running container uses, its base OS and support, and the
    CVEs in its Debian, Ubuntu and Alpine packages, from the package lists the collector sends and the hub's CVE data. The same
    cells as an Unraid system's page. A collector that sends no image data (an older version) gets its images listed from its
    Docker snapshot as not read."""
    import time
    from .. import db, hub
    from ..remote import docker_images
    from . import provenance as prov
    host = cfg.host_id
    snaps = db.get_snapshots(conn, host)
    snap = snaps.get(hub.DOCKER_IMAGES)
    data = snap.data if snap and snap.data else None
    now = time.time()
    empty, unread = None, []
    if data is None:
        dk = snaps.get("docker")
        if dk and dk.data and dk.data.get("available") is not False:
            empty = OLD_COLLECTOR
            by_image: dict[str, list[str]] = {}
            for c in dk.data.get("containers", []):
                by_image.setdefault(c.get("image") or "unknown", []).append(c["name"])
            unread = [{"name": k, "containers": ", ".join(sorted(v)[:3]) + (f" and {len(v) - 3} more" if len(v) > 3 else "")}
                      for k, v in sorted(by_image.items())]
        else:
            empty = "No image data yet. This host has no Docker, or its collector has not read it yet."
    elif data.get("available") is False:
        empty = f"This host sends no image package lists: {data.get('reason') or 'the collector has no Docker to read'}."
    cves = docker_images.load_cves(cfg, conn, host, data) if data else None
    a = docker_images.analyze(data, None, cves) if data else None
    rows = image_rows(a, image_findings(conn, host), True)
    return {"host": views._host(cfg, snaps), "collector": True, "configured": True, "empty": empty, "unread": unread,
            "state": views._source_state(snaps, hub.DOCKER_IMAGES), "ago": fmt_ago(snap.taken_at, now) if snap and data else None,
            "has_data": bool(data) and data.get("available") is not False, "old_reader": False,
            "edit": None, "source_text": "package lists the collector reads from running containers",
            "update_hint": "Update an image: pull a newer tag and create the container again (docker compose pull, then docker compose up -d).",
            **coverage(rows, a, cves, now), "src": {"images": prov.images_section(None, collector=True)}}
