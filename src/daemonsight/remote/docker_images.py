"""What is inside the container images of an Unraid server: each image's base operating system, whether that base
still gets security updates, and the CVEs in its Debian packages. The package lists come from the Docker reader (see
docker_reader.py, "Package lists"; stored by docker_storage.parse_summary as `image_packages`), and the matching is the
hub's CVE matcher (cve/match.py) run on each image as if it were a host.

Per image the analysis gives:

* the base OS (os-release `ID`, `VERSION_ID`, codename) and its support status. Debian, Ubuntu and Fedora use the
  host code (`distro.evaluate`), Alpine and CentOS Linux use endoflife.date's data bundled in data/endoflife
  (`distro.evaluate_image`). A release those do not list is "unknown", never "supported".
* `docker.eol_base` (medium): one aggregate finding for every image whose base has ended support (status "eol", or
  "ended": Debian past LTS, where only the paid ELTS covers it). An image on Debian LTS or Ubuntu ESM still gets some
  updates and is shown, not counted.
* `docker.image_cves`: one finding per Debian image that has CVEs the tracker lists as fixed in a newer version of a
  package the image holds. Severity as for a host (cve/match.py, `package_findings`): High when a fixable CVE is on
  CISA's KEV list or has an EPSS score at or above `[cve] epss_high`, otherwise Medium. CVEs with no fix yet are counted
  and shown as information; they do not raise the finding, because updating the image cannot fix them. (A host's
  `cve.package` also raises High for an unfixed KEV CVE, since the host's owner may mitigate it; an image has nothing
  to apply.) Ubuntu images are counted "Ubuntu matching not built yet" and Alpine ones "Alpine matching next"; neither
  is a finding.

The CVE chore (cve/run.py) matches each image under the pseudo-host id `docker:<host>:<image id>`, which cannot clash
with a real host (a host id has no colon). `load_cves` reads those matches; poll.py gives them to `evaluate` at each
poll, so a finding follows the chore's work within a poll interval.
"""

from __future__ import annotations

from datetime import date

from .. import distro, findings as rules
from ..findings import Finding, digest
from . import docker_storage as ds

LINK = "/images"
ROW = "ci"                                # row anchors: rules.anchor("ci", short id)
DEBIAN_IDS = ("debian", "raspbian")
SHOWN_CVES = 4

HOWTO_EOL = "\n".join((
    "These images are built on an operating system that no longer gets security updates, so a flaw found in one of its packages stays",
    "Update each image: on Unraid, open the Docker tab, press Check for Updates, then apply the update. Or pull a newer tag of the same app",
    "If the app's newest image is still on that base, its maintainer has not rebuilt it. Look for an alternative image of the same app, or ask the maintainer to rebuild on a supported base",
    "The Container images page lists each image with its base and when that base's support ends. DaemonSight only reads and changes nothing"))
HOWTO_CVES = "\n".join((
    "Update the image: on Unraid, open the Docker tab, press Check for Updates, then apply the update. Or pull a newer tag of the same app",
    "Running apt upgrade inside the container does not help: the change is lost when the container is created again",
    "If no newer image exists, the app's maintainer has not rebuilt it yet. Ask them to, or look for an alternative image",
    "The CVEs are listed on the Container images page, each with its exploit score and whether it is on CISA's KEV list",
    "The finding goes away when the image no longer holds the vulnerable package versions"))


# --- the base OS ---------------------------------------------------------------------------------------------------------

def os_name(os_info: dict | None) -> str:
    """"Debian 12" from the os dict (the codename is shown apart); the pretty name when the id is not a known one."""
    if not os_info or not os_info.get("id"):
        return "unknown"
    oid = os_info["id"]
    label = distro.NAMES.get(oid) or os_info.get("pretty") or oid
    version = os_info.get("version_id") or ""
    return " ".join(x for x in (label, version) if x)


def debian_codename(os_info: dict | None) -> str | None:
    """The Debian release name for the tracker: VERSION_CODENAME, else the name of VERSION_ID in Debian's release data
    (an image's os-release can lack the codename). Raspberry Pi OS is Debian under its own name."""
    if not os_info or os_info.get("id") not in DEBIAN_IDS:
        return None
    if os_info.get("codename"):
        return os_info["codename"]
    if os_info.get("version_id"):
        row = distro.find_row(distro.load_rows("debian", os_info["version_id"], None), os_info["version_id"], None)
        if row and row.get("series"):
            return row["series"].lower()
    return None


def match_kind(entry: dict) -> str:
    """How the CVE matcher treats an image: "debian" (matched), "ubuntu" (not yet), "alpine" (next), "other" (an OS
    without dpkg or apk, or a Debian derivative with its own tracker), "unread" (no package list)."""
    oi = entry.get("os") or {}
    if not entry.get("manager"):
        return "unread"
    oid = oi.get("id")
    if oid in DEBIAN_IDS and entry["manager"] == "dpkg":
        return "debian" if debian_codename(oi) else "other"
    if oid == "ubuntu":
        return "ubuntu"
    if oid == "alpine" and entry["manager"] == "apk":
        return "alpine"
    return "other"


def support_of(os_info: dict | None, today: date) -> dict:
    """{"status", "label", "eol", "name", "current"}: the base's support. `label` is what the page shows."""
    sup = distro.evaluate_image(os_info, today)
    if sup.status == "unknown":
        return {"status": "unknown", "label": "Unknown", "eol": None, "name": os_name(os_info), "current": ""}
    if sup.status == "supported":
        label = f"Supported until {sup.eol.isoformat()}" if sup.eol else "Supported"
    elif sup.status == "eol":
        label = f"End of life since {(sup.until or sup.eol).isoformat()}" if (sup.until or sup.eol) else "End of life"
    elif sup.status == "ended" and sup.until:
        label = f"Ended {sup.until.isoformat()}, paid ELTS only"
    else:
        label = sup.label
    # The release's own name ("Alpine 3.17" for 3.17.2): a patch version inside a cycle must not move a finding's basis.
    return {"status": sup.status, "label": label, "eol": sup.eol.isoformat() if sup.eol else None,
            "name": sup.name, "current": sup.current if sup.current_version else ""}


# --- images as the CVE chore matches them -----------------------------------------------------------------------------------

def pseudo_host(host: str, image_id: str) -> str:
    return f"docker:{host}:{image_id.removeprefix('sha256:')[:16]}"


def pseudo_inventory(entry: dict) -> dict | None:
    """The inventory the CVE matcher takes (cve/match.py `match_host`) for a Debian image, or None for any other.
    Packages are grouped by source name and source version, with the binary names listed, as a host's inventory is."""
    if match_kind(entry) != "debian":
        return None
    groups: dict[tuple[str, str], list[str]] = {}
    for name, source, version, src_version in entry["packages"]:
        groups.setdefault((source or name, src_version or version), []).append(name)
    sources = [[s, v, sorted(set(b))[:30]] for (s, v), b in sorted(groups.items())]
    codename = debian_codename(entry["os"])
    return {"backend": "apt", "os_id": "debian", "codename": codename, "sources": sources, "taken_at": entry.get("read_at") or 0,
            "hash": digest([codename or "", *(f"{s}={v}" for s, v, _b in sources)])}


def image_inventories(snapshots: dict[str, dict]) -> dict[str, dict]:
    """pseudo-host id -> inventory, for every Debian image in each system's stored `image_packages`. `snapshots` maps a
    system's id to its stored Docker summary."""
    out = {}
    for host, data in snapshots.items():
        for e in (data or {}).get("image_packages") or []:
            inv = pseudo_inventory(e)
            if inv:
                out[pseudo_host(host, e["image_id"])] = inv
    return out


def load_cves(cfg, state_conn, host: str, data: dict | None) -> dict | None:
    """What the CVE chore found for this system's Debian images, for `evaluate` and the page:
    {"enabled", "available", "epss_high", "feed_at", "images": {image id: {"matched": bool, "cves": [...]}}}.
    None when the stored summary has no package lists."""
    if not data or not data.get("image_packages"):
        return None
    from .. import settings
    from ..cve import match, store
    eff = settings.effective(cfg, state_conn)
    out = {"enabled": eff.cve.enabled, "available": False, "epss_high": eff.cve.epss_high, "feed_at": None, "images": {}}
    if not eff.cve.enabled:
        return out
    cdb = store.connect_reader(cfg.cve_db_path)
    if cdb is None:
        return out
    try:
        out["available"] = True
        feed = cdb.execute("SELECT ok_at FROM feed WHERE name = 'debian'").fetchone()
        out["feed_at"] = feed["ok_at"] if feed else None
        for e in data["image_packages"]:
            if match_kind(e) != "debian":
                continue
            ph = pseudo_host(host, e["image_id"])
            done = cdb.execute("SELECT 1 FROM matched WHERE host = ?", (ph,)).fetchone() is not None
            out["images"][e["image_id"]] = {"matched": done,
                                            "cves": match.host_cves(cdb, ph, ("fix", "nofix")) if done else []}
    finally:
        cdb.close()
    return out


# --- the analysis ---------------------------------------------------------------------------------------------------------------

def _ref(iid: str, containers: list[dict], images: dict[str, dict]) -> str:
    for c in containers:
        ref = c.get("image") or ""
        if ref and not ref.startswith("sha256:") and "@sha256:" not in ref and len(ref) != 64:
            return ref
    img = images.get(iid)
    return ds.image_name(img) if img else ds.short_id(iid)


def cve_summary(cves: list[dict], epss_high: float) -> dict:
    """Counts and the worst CVEs of one image's matches, ranked as a host's are (KEV, then EPSS)."""
    from ..cve import match
    fixable = sorted((c for c in cves if c["state"] == "fix"), key=match.rank_key)
    unfixed = [c for c in cves if c["state"] == "nofix"]
    kev = [c for c in fixable if c["kev"]]
    hot = [c for c in fixable if not c["kev"] and (c["epss"] or 0) >= epss_high]
    return {"fixable": fixable, "unfixed": len(unfixed), "kev": kev, "hot": hot,
            "severity": "high" if kev or hot else "medium" if fixable else None}


def analyze(data: dict | None, unraid_docker: dict | None = None, cves: dict | None = None,
            today: date | None = None) -> dict | None:
    """One row per image a container uses, from the stored summary. None when the reader sent no package lists (a
    reader from before them, or no data)."""
    if not data or data.get("image_packages") is None:
        return None
    today = today or date.today()
    images = {i["id"]: i for i in data.get("images", [])}
    by_image: dict[str, list[dict]] = {}
    for c in data.get("containers", []):
        if c.get("image_id"):
            by_image.setdefault(c["image_id"], []).append(c)
    rows = []
    counts = {"read": 0, "stopped": 0, "waiting": 0, "failed": 0, "other_os": 0, "debian": 0, "ubuntu": 0, "alpine": 0}
    epss_high = (cves or {}).get("epss_high", 0.10)
    for e in data["image_packages"]:
        iid = e["image_id"]
        cs = by_image.get(iid, [])
        name = _ref(iid, cs, images)
        kind = match_kind(e)
        sup = support_of(e["os"], today) if e["os"] else {"status": "unknown", "label": "Unknown", "eol": None, "name": "unknown", "current": ""}
        err = e.get("error") or ""
        if e["manager"]:
            state = "read"
            counts["read"] += 1
        elif err == "not read: stopped":
            state, counts["stopped"] = "stopped", counts["stopped"] + 1
        elif err == "not read yet":
            state, counts["waiting"] = "waiting", counts["waiting"] + 1
        elif err.startswith("packages not read:") and "does not use dpkg or apk" in err:
            state, counts["other_os"] = "other_os", counts["other_os"] + 1
        else:
            state, counts["failed"] = "failed", counts["failed"] + 1
        if kind in counts:
            counts[kind] += 1
        row = {"id": iid, "short": ds.short_id(iid), "anchor": rules.anchor(ROW, ds.short_id(iid)), "name": name, "repo": ds.repo_of(name) or ds.short_id(iid),
               "containers": sorted(c["name"] for c in cs), "running": any(c.get("state") == "running" for c in cs),
               "read_container": e.get("container"),
               "os": e["os"], "os_name": sup["name"], "codename": (e["os"] or {}).get("codename") or "", "support": sup, "kind": kind, "state": state, "error": err or None,
               "manager": e["manager"], "count": e["count"], "read_at": e.get("read_at"),
               "cve": None}
        if kind == "debian":
            m = (cves or {}).get("images", {}).get(iid)
            if cves is None or not cves.get("enabled"):
                row["cve"] = {"state": "off"}
            elif not cves.get("available") or m is None or not m["matched"]:
                row["cve"] = {"state": "pending"}
            else:
                row["cve"] = {"state": "matched", **cve_summary(m["cves"], epss_high)}
        rows.append(row)
    rows.sort(key=lambda r: (r["support"]["status"] not in ("eol", "ended"), -(len((r["cve"] or {}).get("fixable") or [])), r["name"].lower()))
    return {"rows": rows, "counts": counts, "generated": data.get("generated"), "cves": cves,
            "eol": [r for r in rows if r["support"]["status"] in ("eol", "ended")]}


# --- findings ----------------------------------------------------------------------------------------------------------------------

def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def evaluate(data: dict | None, unraid_docker: dict | None = None, cves: dict | None = None,
             today: date | None = None) -> list[Finding]:
    a = analyze(data, unraid_docker, cves, today)
    if not a:
        return []
    from ..cve import match
    out: list[Finding] = []
    eol = a["eol"]
    if eol:
        n = len(eol)
        listed = ", ".join(f"{r['name']} ({r['os_name']})" for r in eol[:6]) + (f" and {n - 6} more" if n > 6 else "")
        out.append(Finding("docker.eol_base", "all", "medium",
                           f"{n} container {_plural(n, 'image runs', 'images run')} on an end-of-life OS",
                           f"{_plural(n, 'This image is', 'These images are')} built on an operating system that no longer gets free security updates: {listed}. "
                           "A flaw found in its packages stays unfixed until the image is rebuilt on a supported base.",
                           f"{LINK}#image-list", None, "eol:" + digest(f"{r['repo']}@{r['os_name']}" for r in eol), HOWTO_EOL))
    for r in a["rows"]:
        c = r["cve"]
        if not c or c["state"] != "matched" or not c["fixable"]:
            continue
        fixable, kev, hot = c["fixable"], c["kev"], c["hot"]
        n = len(fixable)
        title = f"{r['name']} ({r['os_name']}): {n} fixable {_plural(n, 'CVE', 'CVEs')}"
        if kev:
            title += f", {len(kev)} known exploited"
        elif hot:
            title += f", {len(hot)} with a high exploit score"
        top = ", ".join(match._describe(x) for x in fixable[:SHOWN_CVES]) + (f" and {n - SHOWN_CVES} more" if n > SHOWN_CVES else "")
        detail = (f"The image holds package versions that Debian's security tracker lists as fixed in newer ones ({r['os_name']}). "
                  f"Top CVEs: {top}.")
        if c["unfixed"]:
            detail += f" {c['unfixed']} more in the image have no fix yet; they are listed on the page and raise nothing."
        out.append(Finding("docker.image_cves", r["name"], c["severity"], title[:300], detail[:3900],
                           f"{LINK}#{r['anchor']}", None, f"{r['repo']}:{digest(x['cve'] for x in fixable)}", HOWTO_CVES))
    out.sort(key=lambda f: (f.severity != "high", f.rule, f.title))
    return out
