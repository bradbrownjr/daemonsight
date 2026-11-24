"""What is inside the container images of an Unraid server: each image's base operating system, whether that base
still gets security updates, and the CVEs in its Debian and Ubuntu packages (and Alpine's, from secdb). The package lists come from the Docker reader (see
docker_reader.py, "Package lists"; stored by docker_storage.parse_summary as `image_packages`), and the matching is the
hub's CVE matcher (cve/match.py) run on each image as if it were a host.

Per image the analysis gives:

* the base OS (os-release `ID`, `VERSION_ID`, codename) and its support status. Debian, Ubuntu and Fedora use the
  host code (`distro.evaluate`), Alpine and CentOS Linux use endoflife.date's data bundled in data/endoflife
  (`distro.evaluate_image`). A release those do not list is "unknown", never "supported".
* `docker.eol_base` (medium): one aggregate finding for every image whose base has ended support (status "eol", or
  "ended": Debian past LTS, where only the paid ELTS covers it). An image on Debian LTS or Ubuntu ESM still gets some
  updates and is shown, not counted.
* `docker.image_cves`: one finding per Debian, Ubuntu or Alpine image that has CVEs the Debian tracker, Canonical's Ubuntu OVAL
  (cve/ubuntu.py) or Alpine's secdb (cve/alpine.py) lists as fixed in a newer version of a package the image holds. A fix that
  exists only in Ubuntu Pro's ESM archives is not one an image can take, so it is counted and shown, never raised. Severity and
  deadline as for a host (cve/priority.py, CISA BOD 26-04): the worst fixable CVE of the image, rated for the image's exposure
  (cve/exposure.py `image_exposures`: exposed when a running container from it publishes a port that an OPNsense port forward or
  Caddy site sends the internet to). CVEs with no fix yet are counted and shown as information; they do not raise the finding,
  because updating the image cannot fix them. (A host's `cve.package` also raises for an unfixed KEV CVE, since the host's owner
  may mitigate it; an image has nothing to apply.) Alpine's secdb only records fixes, so an Alpine image has no unfixed count.

The CVE chore (cve/run.py) matches each image under the pseudo-host id `docker:<host>:<image id>`, which cannot clash
with a real host (a host id has no colon). `load_cves` reads those matches; poll.py gives them to `evaluate` at each
poll, so a finding follows the chore's work within a poll interval.
"""

from __future__ import annotations

from datetime import date
from functools import cmp_to_key

from .. import distro, findings as rules
from ..cve import alpine, apkver, exposure as cve_exposure, priority, ubuntu
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
HOWTO_CVES_ALPINE = "\n".join((
    "Update the image: on Unraid, open the Docker tab, press Check for Updates, then apply the update. Or pull a newer tag of the same app",
    "Running apk upgrade inside the container does not help: the change is lost when the container is created again",
    "If no newer image exists, the app's maintainer has not rebuilt it yet. Ask them to, or look for an alternative image",
    "The CVEs are listed on the Container images page, each with its deadline, exploit probability and whether it is on CISA's KEV list",
    "The finding goes away when the image no longer holds the vulnerable package versions"))
HOWTO_CVES = "\n".join((
    "Update the image: on Unraid, open the Docker tab, press Check for Updates, then apply the update. Or pull a newer tag of the same app",
    "Running apt upgrade inside the container does not help: the change is lost when the container is created again",
    "If no newer image exists, the app's maintainer has not rebuilt it yet. Ask them to, or look for an alternative image",
    "The CVEs are listed on the Container images page, each with its deadline, exploit probability and whether it is on CISA's KEV list",
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


def ubuntu_codename(os_info: dict | None) -> str | None:
    """The Ubuntu release name for Canonical's data: VERSION_CODENAME, else the name of VERSION_ID in the release data (an old
    image's os-release can lack the codename)."""
    if not os_info or os_info.get("id") != "ubuntu":
        return None
    name = (os_info.get("codename") or "").lower()
    if name:
        return name if ubuntu.CODENAME_RE.match(name) else None
    if os_info.get("version_id"):
        row = distro.find_row(distro.load_rows("ubuntu", os_info["version_id"], None), os_info["version_id"], None)
        if row and row.get("series"):
            return row["series"].lower()
    return None


def match_kind(entry: dict) -> str:
    """How the CVE matcher treats an image: "debian" and "ubuntu" (matched against the distribution's data once the release
    has a name), "alpine" (matched against secdb when its release has a name), "other" (an OS without dpkg or apk, or a
    derivative with its own id), "unread" (no package list)."""
    oi = entry.get("os") or {}
    if not entry.get("manager"):
        return "unread"
    oid = oi.get("id")
    if oid in DEBIAN_IDS and entry["manager"] == "dpkg":
        return "debian" if debian_codename(oi) else "other"
    if oid == "ubuntu" and entry["manager"] == "dpkg":
        return "ubuntu" if ubuntu_codename(oi) else "other"
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


def alpine_release(os_info: dict | None) -> str | None:
    """secdb's directory for an Alpine image ("v3.23" for 3.23.2), or None for any other OS or an unnamed release."""
    if not os_info or os_info.get("id") != "alpine":
        return None
    return alpine.release_of(os_info.get("version_id"))


def _alpine_inventory(entry: dict) -> dict | None:
    """The inventory of an Alpine image: its packages grouped by origin, one version each. Subpackages of one origin are
    built together and normally share a version; when they differ (an `apk add` of one subpackage from a newer index), the
    lowest is used and the note says so. A version apk does not parse is left out and counted."""
    release = alpine_release(entry["os"])
    if not release:
        return None
    groups: dict[str, dict[str, list[str]]] = {}
    skipped = 0
    for name, origin, version, _src_version in entry["packages"]:
        if not apkver.valid(version):
            skipped += 1
            continue
        groups.setdefault(origin or name, {}).setdefault(version, []).append(name)
    sources, mixed = [], []
    for origin, versions in sorted(groups.items()):
        lowest = min(versions, key=cmp_to_key(apkver.compare))
        if len(versions) > 1:
            mixed.append(origin)
        sources.append([origin, lowest, sorted({n for names in versions.values() for n in names})[:30]])
    notes = []
    if mixed:
        listed = ", ".join(mixed[:3]) + (f" and {len(mixed) - 3} more" if len(mixed) > 3 else "")
        notes.append(f"{len(mixed)} {'origin has' if len(mixed) == 1 else 'origins have'} subpackages at different versions, "
                     f"matched at the lowest ({listed})")
    if skipped:
        notes.append(f"{skipped} {'package has a version' if skipped == 1 else 'packages have versions'} apk cannot parse and "
                     f"{'was' if skipped == 1 else 'were'} skipped")
    return {"backend": "apk", "os_id": "alpine", "release": release, "sources": sources, "note": "; ".join(notes),
            "taken_at": entry.get("read_at") or 0,
            "hash": digest([release, "; ".join(notes), *(f"{s}={v}" for s, v, _b in sources)])}


def pseudo_inventory(entry: dict) -> dict | None:
    """The inventory the CVE matcher takes (cve/match.py `match_host`, cve/ubuntu.py `match_host`, cve/alpine.py `match_host`) for a
    Debian, Ubuntu or Alpine image, or None for any other. Debian packages are grouped by source name and source version, with the binary names
    listed, as a host's inventory is; Alpine ones by origin."""
    kind = match_kind(entry)
    if kind == "alpine":
        return _alpine_inventory(entry)
    if kind not in ("debian", "ubuntu"):
        return None
    groups: dict[tuple[str, str], list[str]] = {}
    for name, source, version, src_version in entry["packages"]:
        groups.setdefault((source or name, src_version or version), []).append(name)
    sources = [[s, v, sorted(set(b))[:30]] for (s, v), b in sorted(groups.items())]
    if kind == "ubuntu":
        codename = ubuntu_codename(entry["os"])
        # An image has no Ubuntu Pro: `esm` is an empty list, not unknown, so a fix only in the ESM archives is not an available one.
        return {"backend": "apt", "os_id": "ubuntu", "codename": codename, "version_id": (entry["os"] or {}).get("version_id"),
                "esm": [], "sources": sources, "taken_at": entry.get("read_at") or 0,
                "hash": digest(["ubuntu", codename or "", *(f"{s}={v}" for s, v, _b in sources)])}
    codename = debian_codename(entry["os"])
    return {"backend": "apt", "os_id": "debian", "codename": codename, "sources": sources, "taken_at": entry.get("read_at") or 0,
            "hash": digest([codename or "", *(f"{s}={v}" for s, v, _b in sources)])}


def image_inventories(snapshots: dict[str, dict]) -> dict[str, dict]:
    """pseudo-host id -> inventory, for every Debian, Ubuntu and Alpine image in each system's stored `image_packages`. `snapshots` maps a
    system's id to its stored Docker summary."""
    out = {}
    for host, data in snapshots.items():
        for e in (data or {}).get("image_packages") or []:
            inv = pseudo_inventory(e)
            if inv:
                out[pseudo_host(host, e["image_id"])] = inv
    return out


def _alpine_state(cdb, release: str) -> dict:
    """How secdb stands for one release, from its two files' feed rows: {"state": "ok" | "absent" | "pending", "ok_at",
    "error"}. `absent`: secdb has no file for the release. `pending`: not fetched yet. `error` holds the last failed
    try's reason while an older copy (or none) is in use."""
    from ..cve import feeds
    rows = cdb.execute("SELECT name, status, ok_at, detail FROM feed WHERE name IN (?, ?)",
                       tuple(f.name for f in feeds.alpine_feeds(release))).fetchall()
    err = next((r["detail"] for r in rows if r["status"] == "error" and r["detail"]), None)
    if len(rows) < 2 or any(r["ok_at"] is None for r in rows):
        return {"state": "pending", "ok_at": None, "error": err}
    state = "absent" if all(r["status"] == "absent" for r in rows) else "ok"
    return {"state": state, "ok_at": min(r["ok_at"] for r in rows), "error": err}


def _ubuntu_state(cdb, release: str) -> dict:
    """How Canonical's OVAL stands for one release, from its feed row: {"state": "ok" | "absent" | "pending", "ok_at",
    "error"}. `absent`: the source has no file for the release. `pending`: not fetched yet."""
    from ..cve import feeds
    r = cdb.execute("SELECT status, ok_at, detail FROM feed WHERE name = ?", (feeds.ubuntu_feed(release).name,)).fetchone()
    if r is None or r["ok_at"] is None:
        return {"state": "pending", "ok_at": None, "error": r["detail"] if r and r["status"] == "error" else None}
    return {"state": "absent" if r["status"] == "absent" else "ok", "ok_at": r["ok_at"],
            "error": r["detail"] if r["status"] == "error" else None}


def load_cves(cfg, state_conn, host: str, data: dict | None) -> dict | None:
    """What the CVE chore found for this system's Debian, Ubuntu and Alpine images, for `evaluate` and the page:
    {"enabled", "available", "epss_automatable", "feed_at", "alpine": {release: {"state", "ok_at", "error"}},
    "ubuntu": {codename: {...the same}}, "images": {image id: {"matched": bool, "cves": [...], "note": str, "exposure": cve/exposure.Exposure}}}.
    None when the stored summary has no package lists."""
    if not data or not data.get("image_packages"):
        return None
    from .. import settings
    from ..cve import match, store
    eff = settings.effective(cfg, state_conn)
    priority.use(eff.data_dir)
    out = {"enabled": eff.cve.enabled, "available": False, "epss_automatable": eff.cve.epss_automatable, "feed_at": None, "alpine": {},
           "ubuntu": {}, "images": {}}
    if not eff.cve.enabled:
        return out
    cdb = store.connect_reader(cfg.cve_db_path)
    if cdb is None:
        return out
    from .. import db
    snap = db.get_snapshot(state_conn, host, "unraid_docker")
    exposures = cve_exposure.image_exposures(state_conn, host, data, snap.data if snap and snap.data else None)
    try:
        out["available"] = True
        feed = cdb.execute("SELECT ok_at FROM feed WHERE name = 'debian'").fetchone()
        out["feed_at"] = feed["ok_at"] if feed else None
        for e in data["image_packages"]:
            kind = match_kind(e)
            if kind not in ("debian", "alpine", "ubuntu"):
                continue
            release = alpine_release(e["os"]) if kind == "alpine" else ubuntu_codename(e["os"]) if kind == "ubuntu" else None
            pending = False
            if kind == "alpine":
                if not release:
                    continue                     # no release name to look up: the page says so
                if release not in out["alpine"]:
                    out["alpine"][release] = _alpine_state(cdb, release)
                pending = out["alpine"][release]["state"] == "pending"
            elif kind == "ubuntu":
                if release not in out["ubuntu"]:
                    out["ubuntu"][release] = _ubuntu_state(cdb, release)
                pending = out["ubuntu"][release]["state"] == "pending"
            ph = pseudo_host(host, e["image_id"])
            row = cdb.execute("SELECT note, inv_hash FROM matched WHERE host = ?", (ph,)).fetchone()
            inv = pseudo_inventory(e)
            # Matches made for other package lists (the image was rebuilt or read again since) are not this image's yet.
            done = row is not None and not pending and (inv is None or row["inv_hash"] == inv["hash"])
            out["images"][e["image_id"]] = {"matched": done, "note": (row["note"] or "") if row else "",
                                            "exposure": exposures.get(e["image_id"]) or cve_exposure.unknown([]),
                                            "cves": match.host_cves(cdb, ph, ("fix", "esm", "nofix")) if done else []}
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


def cve_summary(cves: list[dict], epss_automatable: float, exposure=None) -> dict:
    """Counts and the worst CVEs of one image's matches, most urgent first (CISA BOD 26-04 timeline, then EPSS: cve/priority.py),
    each gaining its "rating". `exposure` is the image's (cve/exposure.Exposure). The image's severity is its worst fixable CVE's."""
    from ..cve import match
    exposure = exposure or cve_exposure.unknown([])
    priority.attach(cves, exposure.exposed, epss_automatable)
    fixable = [c for c in cves if c["state"] == "fix"]
    unfixed = [c for c in cves if c["state"] == "nofix"]
    esm = [c for c in cves if c["state"] == "esm"]       # Ubuntu: fixed only in the Pro archives
    kev = [c for c in fixable if c["kev"]]
    worst = fixable[0] if fixable else None
    return {"fixable": fixable, "unfixed": len(unfixed), "esm": esm, "kev": kev, "worst": worst, "exposure": exposure,
            "severity": worst["rating"].severity if worst else None}


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
    epss_auto = (cves or {}).get("epss_automatable", 0.04)
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
        if kind in ("debian", "alpine", "ubuntu"):
            m = (cves or {}).get("images", {}).get(iid)
            release = alpine_release(e["os"]) if kind == "alpine" else None
            row["alpine_release"] = release
            row["ubuntu_release"] = ubuntu_codename(e["os"]) if kind == "ubuntu" else None
            if cves is None or not cves.get("enabled"):
                row["cve"] = {"state": "off"}
            elif kind == "alpine" and not release:
                row["cve"] = {"state": "unmapped"}
            elif not cves.get("available") or m is None or not m["matched"]:
                row["cve"] = {"state": "pending"}
            elif kind == "alpine" and (cves.get("alpine") or {}).get(release, {}).get("state") == "absent":
                row["cve"] = {"state": "absent", "release": release, "label": alpine.display(release)}
            elif kind == "ubuntu" and (cves.get("ubuntu") or {}).get(row["ubuntu_release"], {}).get("state") == "absent":
                row["cve"] = {"state": "absent", "release": row["ubuntu_release"], "label": os_name(e["os"])}
            else:
                row["cve"] = {"state": "matched", "note": m.get("note") or "", **cve_summary(m["cves"], epss_auto, m.get("exposure"))}
        rows.append(row)
    rows.sort(key=lambda r: (r["support"]["status"] not in ("eol", "ended"),
                             (r["cve"]["worst"]["rating"].order if (r["cve"] or {}).get("worst") else (10 ** 7,)), r["name"].lower()))
    return {"rows": rows, "counts": counts, "generated": data.get("generated"), "cves": cves,
            "eol": [r for r in rows if r["support"]["status"] in ("eol", "ended")]}


# --- findings ----------------------------------------------------------------------------------------------------------------------

def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _images_present(data: dict) -> set[str]:
    """Every name an image of this system goes by, from the reader's image list and the containers (never the package state)."""
    images = {i["id"]: i for i in data.get("images", [])}
    by_image: dict[str, list[dict]] = {}
    for c in data.get("containers", []):
        if c.get("image_id"):
            by_image.setdefault(c["image_id"], []).append(c)
    names = {t for i in images.values() for t in i.get("tags", [])}
    names |= {_ref(iid, by_image.get(iid, []), images) for iid in images.keys() | by_image.keys()}
    names |= {c["image"] for c in data.get("containers", []) if c.get("image")}
    return names


def _unknown(rows: list[dict]) -> bool:
    """Some image of this name has no answer yet: packages not read (yet), the read failed, or the CVE data is not matched for it."""
    return any(r["state"] in ("waiting", "stopped", "failed") or (r["cve"] or {}).get("state") in ("pending", "unmapped", "absent")
               for r in rows)


def _held_images(a: dict, data: dict, emitted: set[str], prior: dict) -> list[Finding]:
    """The open `docker.image_cves` findings that must stay. A finding resolves only when the image was matched with no fixable CVE
    left, or is no longer on the system (not in the reader's image list and used by no container). An image whose packages are
    not read yet, whose read failed or whose matches are pending keeps its finding as it was."""
    by_name: dict[str, list[dict]] = {}
    for r in a["rows"]:
        by_name.setdefault(r["name"], []).append(r)
    present = None
    out = []
    for rule, key in sorted(prior):
        if rule != "docker.image_cves" or key in emitted:
            continue
        rows = by_name.get(key)
        if rows is None:
            present = _images_present(data) if present is None else present
            keep = key in present
        else:
            keep = _unknown(rows)
        if keep:
            out.append(rules.held(prior, rule, key))
    return out


def evaluate(data: dict | None, unraid_docker: dict | None = None, cves: dict | None = None,
             today: date | None = None, prior: dict | None = None) -> list[Finding]:
    """`prior` maps (rule, key) to this system's open findings. Without package data at all (no summary, a reader from before
    package lists, an empty list) every open `docker.image_cves` finding is emitted unchanged."""
    a = analyze(data, unraid_docker, cves, today)
    if not a or not data.get("image_packages"):
        return [rules.held(prior, *k) for k in sorted(prior or {}) if k[0] == "docker.image_cves"]
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
        fixable, kev = c["fixable"], c["kev"]
        n = len(fixable)
        top = c["worst"]["rating"]
        title = f"{r['name']} ({r['os_name']}): {n} fixable {_plural(n, 'CVE', 'CVEs')}"
        if kev:
            title += f", {len(kev)} known exploited"
        title += "; " + top.deadline.split(" (")[0][0].lower() + top.deadline.split(" (")[0][1:]
        label = "Ubuntu priority" if r["kind"] == "ubuntu" else "Debian urgency"
        shown = ", ".join(match._describe(x, label) for x in fixable[:SHOWN_CVES]) + (f" and {n - SHOWN_CVES} more" if n > SHOWN_CVES else "")
        source = {"alpine": "Alpine's security database (secdb)", "ubuntu": "Canonical's Ubuntu OVAL data"}.get(r["kind"], "Debian's security tracker")
        lead, why = match.finding_text(c["worst"], c["exposure"].why)
        detail = (f"{lead} The image holds package versions that {source} lists as fixed in newer ones ({r['os_name']}). "
                  f"Top CVEs: {shown}.")
        if c["unfixed"]:
            detail += f" {c['unfixed']} more in the image have no fix yet; they are listed on the page and raise nothing."
        if c.get("esm"):
            detail += (f" {len(c['esm'])} more are fixed only in Ubuntu Pro's ESM archives, which an image cannot use; "
                       "they are listed on the page and raise nothing.")
        out.append(Finding("docker.image_cves", r["name"], c["severity"], title[:300], detail[:3900],
                           f"{LINK}#{r['anchor']}", None, f"{r['repo']}:{digest(x['cve'] for x in fixable)}",
                           "\n".join(((HOWTO_CVES_ALPINE if r["kind"] == "alpine" else HOWTO_CVES).split("\n") + why))[:3900]))
    if prior and (cves or {}).get("enabled"):          # with CVE matching switched off the findings go, as before
        out += _held_images(a, data, {f.key for f in out if f.rule == "docker.image_cves"}, prior)
    out.sort(key=lambda f: (priority.SEV_ORDER.index(f.severity), f.rule, f.title))
    return out
