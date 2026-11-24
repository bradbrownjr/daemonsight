"""The pages that add and manage a host that uploads through a collector (Hosts, Add a Linux host, Manage).
They call the functions behind `daemonsight hub add-host | update | revoke` in hub.py, so the web and the CLI
do the same thing. Hub only; every page needs the login, every POST refuses a cross-site request (as the
other hub actions do), and each action leaves an event under "Recent hub changes".

A token is shown once, in the response to the POST that made it. It is not stored (only its SHA-256 is), not
logged and not put in a redirect or a flash message, and the page is `Cache-Control: no-store`.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .. import db, hub
from ..config import Config
from . import views

log = logging.getLogger("daemonsight.hosts")

NAME_HINT = ("Letters, digits, '.', '_' and '-', starting with a letter or digit (63 at most); no spaces.")

# The actions that have a confirmation page first.
ACTIONS = ("token", "revoke", "remove")


def add_host_routes(app: FastAPI, cfg: Config, conn, *, render, require_login, flash) -> None:

    def post_guard(request: Request) -> None:
        require_login(request)
        if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")

    def client(request: Request) -> str:
        return request.client.host if request.client else "?"

    def by(request: Request) -> str:
        return str(request.session.get("user") or "admin")

    def event(request: Request, title: str, detail: str | None = None) -> None:
        db.add_event(conn, db.HUB_HOST, time.time(), "setting", title,
                     detail=f"by {by(request)}" + (f"; {detail}" if detail else ""))

    def collector_host(host: str):
        row = conn.execute("SELECT * FROM hosts WHERE id = ? AND kind IS NULL", (host,)).fetchone() \
            if hub.HOST_RE.match(host) else None
        if row is None:
            raise HTTPException(404)
        return row

    def ingest_url(request: Request) -> str:
        return str(request.base_url).rstrip("/") + "/api/v1/ingest"

    def refused(request: Request):
        """None when the POST may go ahead; the response to send when it may not."""
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        return None

    def token_page(request: Request, host: str, token: str, replaced: bool):
        response = render(request, "host_token.html", {
            "page": "hosts", "v": {"host": None}, "name": host, "token": token, "url": ingest_url(request),
            "replaced": replaced})
        response.headers["Cache-Control"] = "no-store"
        return response

    # --- Add a Linux host -----------------------------------------------------
    def add_form(request: Request, name: str = "", problem: str | None = None, status: int = 200):
        return render(request, "host_new.html", {"page": "hosts", "v": {"host": None}, "name": name,
                                                 "problem": problem}, status)

    @app.get("/hosts/new")
    async def new_form(request: Request):
        require_login(request)
        return add_form(request)

    @app.post("/hosts/new")
    async def new_post(request: Request, name: str = Form("")):
        if (bad := refused(request)) is not None:
            return bad
        name = name.strip()[:80]
        if not name:
            return add_form(request, name, "Name: type a name for this host, e.g. vps.", 400)
        if not hub.HOST_RE.match(name):
            return add_form(request, name, "Name: use letters, digits, '.', '_' and '-', starting with a letter "
                                           "or digit (63 at most); no spaces.", 400)
        try:
            token = hub.add_host(conn, name)
        except ValueError as exc:
            return add_form(request, name, f"Name: {exc}", 400)
        event(request, f"Host added: {name}", "a collector host, waiting for its first upload")
        log.info("Host %s added from %s", name, client(request))
        return token_page(request, name, token, False)

    # --- Manage ---------------------------------------------------------------
    def update_facts(row, target: str | None) -> dict:
        """The Version card: what the host runs, what the hub runs, and whether Update now is on (and if not, why)."""
        st = views._update_state(row, target, time.time())
        reason = ""
        if row["update_to"]:
            reason = st["updating"] + ". It installs it with its next upload."
        elif row["remote_update"] == 0:
            reason = "This host has updates from the hub turned off."
        elif row["last_seen"] is None:
            reason = "This host has not reported yet, so its version is not known."
        elif not target:
            reason = "The hub's own commit is not known, so there is nothing to update to."
        elif not st["can_update"]:
            reason = "This host runs the hub's version."
        return {"host_version": row["version"] or "not reported yet", "hub_version": hub.full_version(),
                "target": target[:7] if target else None, "can_update": st["can_update"], "reason": reason,
                "updating": bool(row["update_to"]), "note": st["update_note"]}

    @app.get("/hosts/{host}/manage")
    async def manage(request: Request, host: str):
        require_login(request)
        if hub.HOST_RE.match(host) and conn.execute("SELECT 1 FROM remotes WHERE id = ?", (host,)).fetchone():
            return RedirectResponse(f"/remotes/{host}/edit", status_code=303)
        row = collector_host(host)
        silent = conn.execute("SELECT 1 FROM findings WHERE host = ? AND rule = 'host.silent' "
                              "AND resolved_at IS NULL", (host,)).fetchone()
        state = "Never reported" if row["last_seen"] is None else ("Not reporting" if silent else "Reporting")
        return render(request, "host_manage.html", {
            "page": "hosts", "v": {"host": None}, "h": row, "state": state,
            "seen": views.fmt_ago(row["last_seen"]) if row["last_seen"] else "never",
            "ver": update_facts(row, hub.hub_revision())})

    @app.post("/hosts/{host}/update")
    async def update(request: Request, host: str, action: str = Form("update")):
        if (bad := refused(request)) is not None:
            return bad
        row = collector_host(host)
        target = hub.hub_revision()
        if action == "cancel":
            if hub.cancel_update(conn, host):
                event(request, f"Update cancelled: {host}")
                flash(request, f"Cancelled the update of {host}.")
            else:
                flash(request, f"{host} has no update waiting.", error=True)
        elif not update_facts(row, target)["can_update"]:
            flash(request, f"{host} is not behind, so there is nothing to ask for.", error=True)
        else:
            hub.request_update(conn, host, target, time.time())
            event(request, f"Update requested: {host}", f"to {target[:7]}")
            log.info("Update to %s requested for %s from %s", target, host, client(request))
            flash(request, f"Asked {host} to update to {target[:7]}. It picks that up with its next upload.")
        return RedirectResponse(f"/hosts/{host}/manage", status_code=303)

    @app.get("/hosts/{host}/manage/{action}")
    async def confirm(request: Request, host: str, action: str):
        require_login(request)
        if action not in ACTIONS:
            raise HTTPException(404)
        row = collector_host(host)
        counts = hub.data_counts(conn, host, cfg.cve_db_path) if action == "remove" else []
        return render(request, "host_confirm.html", {"page": "hosts", "v": {"host": None}, "h": row, "action": action,
                                                     "counts": counts})

    @app.post("/hosts/{host}/token")
    async def replace_token(request: Request, host: str):
        if (bad := refused(request)) is not None:
            return bad
        collector_host(host)
        token = hub.replace_token(conn, host)
        if token is None:
            raise HTTPException(404)
        event(request, f"Upload token replaced: {host}", "the old token no longer works")
        log.info("Upload token of %s replaced from %s", host, client(request))
        return token_page(request, host, token, True)

    @app.post("/hosts/{host}/revoke")
    async def revoke(request: Request, host: str):
        if (bad := refused(request)) is not None:
            return bad
        collector_host(host)
        hub.revoke_host(conn, host, purge=False, data_dir=cfg.data_dir)
        event(request, f"Host revoked: {host}", "its token no longer works; its history is kept")
        log.info("Host %s revoked from %s", host, client(request))
        flash(request, f"Revoked {host}: its token no longer works. Its history is kept.")
        return RedirectResponse("/", status_code=303)

    @app.post("/hosts/{host}/remove")
    async def remove(request: Request, host: str, confirm: str = Form("")):
        if (bad := refused(request)) is not None:
            return bad
        collector_host(host)
        if confirm.strip() != host:
            flash(request, f"To remove {host}, type its name to confirm.", error=True)
            return RedirectResponse(f"/hosts/{host}/manage/remove", status_code=303)
        counts = hub.data_counts(conn, host, cfg.cve_db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            hub.revoke_host(conn, host, purge=True, data_dir=cfg.data_dir, cve_path=cfg.cve_db_path)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        event(request, f"Host removed: {host}", "its token and its stored data are deleted")
        log.info("Host %s removed from %s (%s rows)", host, client(request), sum(n for _l, n in counts))
        flash(request, f"Removed {host}: its token and its stored data are deleted.")
        return RedirectResponse("/", status_code=303)
