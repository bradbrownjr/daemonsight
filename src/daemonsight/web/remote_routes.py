"""The pages that add, edit, disable and remove a system the hub reads over its
API (Hosts, Add a system). Hub only; every page needs the login and every POST
refuses a cross-site request, like the other hub actions.

The API key is typed here once. It is held in the hub's memory for ten
minutes so Test connection and Save don't make you type it twice (the page
carries only a random token for it), then written to a 0600 file by
remote/store.py. It is never put into a page, a log line or the database.
"""

from __future__ import annotations

import logging
import secrets
import time

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .. import db, hub
from ..config import Config
from . import views
from ..remote import opnsense, poll, roles, store, unraid
from ..remote.client import (Net, RemoteError, clean_fingerprint, fingerprint, fmt_fingerprint, normalize_url)

log = logging.getLogger("daemonsight.remote")
PENDING_SECONDS = 600
PENDING_MAX = 20


class Pending:
    """Keys typed into a form and not yet saved, in memory only."""

    def __init__(self):
        self._items: dict[str, tuple[float, str]] = {}

    def _sweep(self) -> None:
        now = time.monotonic()
        for k in [k for k, (exp, _v) in self._items.items() if exp < now]:
            del self._items[k]

    def put(self, key: str, token: str | None = None) -> str:
        self._sweep()
        if token not in self._items:
            while len(self._items) >= PENDING_MAX:
                self._items.pop(next(iter(self._items)))
            token = secrets.token_urlsafe(16)
        self._items[token] = (time.monotonic() + PENDING_SECONDS, key)
        return token

    def get(self, token: str | None) -> str | None:
        self._sweep()
        item = self._items.get(token or "")
        return item[1] if item else None

    def drop(self, token: str | None) -> None:
        self._items.pop(token or "", None)


def _facts_opnsense(p: opnsense.Probe) -> list[tuple[str, str]]:
    return list(p.facts)


def _facts(p: unraid.Probe) -> list[tuple[str, str]]:
    out = [("Server name", p.name or "?"), ("Unraid version", p.version or "?"),
           ("Array", (p.array_state or "?").replace("_", " ").capitalize())]
    if p.disks is not None:
        out.append(("Disks", str(p.disks)))
    if p.containers is not None:
        out.append(("Containers", str(p.containers)))
    return out


def opnsense_rules_roles(data: dict) -> dict[str, str]:
    """The role DaemonSight works out for each interface with no override: {id: role}."""
    return {k: v["role"] for k, v in roles.assign((data.get("interfaces") or {}).get("interfaces", [])).items()}


def add_remote_routes(app: FastAPI, cfg: Config, conn, *, render, require_login, flash, net: Net) -> None:
    pending = Pending()

    def post_guard(request: Request) -> None:
        require_login(request)
        if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")

    def client(request: Request) -> str:
        return request.client.host if request.client else "?"

    def page(request: Request, ctx: dict, status: int = 200):
        row = ctx.get("existing")
        last = None
        if row is not None:
            row = store.get(conn, row["id"]) or row
            last = {"polled": views.fmt_ago(row["last_poll"]) if row["last_poll"] else None,
                    "ok": views.fmt_ago(row["last_ok"]) if row["last_ok"] else None,
                    "error": (row["last_error"] or "")[:300] if row["fails"] else None}
        return render(request, "remote_form.html", {"page": "remotes", "v": {"host": None}, "last": last, **ctx}, status)

    def blank(existing=None) -> dict:
        return {"kind": existing["kind"] if existing else "unraid", "name": existing["id"] if existing else "",
                "url": existing["url"] if existing else "",
                "tls": existing["tls"] if existing else "verify",
                "pin_confirm": fmt_fingerprint(existing["tls_pin"]) if existing and existing["tls_pin"] else "",
                "interval": existing["interval"] if existing else store.DEFAULT_INTERVAL,
                "enabled": bool(existing["enabled"]) if existing else True, "pending": ""}

    async def work(request: Request, form: dict, existing, action: str):
        """Check the form, look at the server, and (on Save) store it. Returns
        (context for the page, redirect or None)."""
        ctx = {"f": form, "existing": existing, "problems": [], "result": None, "cert": None, "KINDS": store.KINDS, "GUIDES": store.GUIDES}
        problems = ctx["problems"]
        # --- the fields
        kind = existing["kind"] if existing is not None else form["kind"]
        if kind not in store.KINDS:
            problems.append("Pick the kind of system.")
            return ctx, None
        two = kind in store.TWO_PART
        form["kind"] = kind
        if existing is None:
            if not hub.HOST_RE.match(form["name"]):
                problems.append("Name: use letters, digits, '.', '_' and '-', starting with a letter or digit (63 at most).")
            elif conn.execute("SELECT 1 FROM hosts WHERE id = ?", (form["name"],)).fetchone():
                problems.append(f"Name: {form['name']} already exists.")
        try:
            url = normalize_url(form["url"], kind)
            form["url"] = url
        except ValueError as exc:
            problems.append(f"Address: {exc}")
            url = None
        try:
            interval = store.valid_interval(form["interval"])
        except ValueError as exc:
            problems.append(f"Interval: {exc}")
            interval = None
        # --- the key: typed now, or kept in memory from the last Test, or already saved. OPNsense has a key and a
        # secret: held together ("key secret": neither contains a space), typed together or not at all.
        typed = form.pop("key", "")
        typed_secret = form.pop("secret", "")
        key, secret, key_new = None, None, False
        if typed.strip() or (two and typed_secret.strip()):
            try:
                if two:
                    key, secret, key_new = store.clean_opnsense_key(typed), store.clean_secret(typed_secret), True
                else:
                    key, key_new = store.clean_key(typed), True
            except ValueError as exc:
                problems.append(str(exc) if not two else f"{exc} Enter the key and the secret from the downloaded file, both.")
        else:
            held = pending.get(form["pending"])
            if held is not None:
                key, secret = (held.split(" ", 1) + [None])[:2] if two else (held, None)
                key_new = True
            elif existing:
                if two:
                    key, secret = store.read_credentials(cfg.data_dir, existing["id"]) or (None, None)
                else:
                    key = store.read_key(cfg.data_dir, existing["id"])
            if key is None or (two and not secret):
                key, secret = None, None
                problems.append("API key and secret: enter both." if two else "API key: enter the key.")
        if key is not None and key_new:
            form["pending"] = pending.put(f"{key} {secret}" if two else key, form["pending"] or None)
        disabling = existing is not None and not form["enabled"]
        if problems or url is None or key is None:
            return ctx, None
        if disabling and action == "save" and not key_new:
            store.update(conn, cfg.data_dir, existing["id"], url=url, tls=existing["tls"], pin=existing["tls_pin"],
                         cert=existing["tls_cert"], interval=interval, enabled=False, key=key if key_new else None,
                         secret=secret if key_new else None)
            poll._set_unreachable(conn, store.get(conn, existing["id"]), time.time(), None)
            log.info("System %s disabled from %s", existing["id"], client(request))
            pending.drop(form["pending"])
            flash(request, f"Saved {existing['id']} (disabled).")
            return ctx, RedirectResponse("/", status_code=303)
        # --- TLS
        pem, tls = None, form["tls"] if form["tls"] in ("verify", "pin") else "verify"
        form["tls"] = tls
        try:
            if tls == "pin":
                pem = await net.certificate(url)
                fp = fingerprint(pem)
                confirmed = clean_fingerprint(form["pin_confirm"]) == fp
                ctx["cert"] = {"fp": fmt_fingerprint(fp), "confirmed": confirmed,
                               "changed": bool(clean_fingerprint(form["pin_confirm"])) and not confirmed}
                if not confirmed:
                    form["pin_confirm"] = ""
                    return ctx, None
                form["pin_confirm"] = fmt_fingerprint(fp)
            result = (await opnsense.probe(net, url, key, secret, tls, pem) if two else await unraid.probe(net, url, key, tls, pem))
        except RemoteError as exc:
            if exc.kind == "tls" and tls == "verify":
                # Probably Unraid's self-signed certificate. Offer to pin it; nothing was sent beyond the handshake.
                try:
                    pem = await net.certificate(url)
                    form["tls"], form["pin_confirm"] = "pin", ""
                    ctx["cert"] = {"fp": fmt_fingerprint(fingerprint(pem)), "confirmed": False, "changed": False,
                                   "offer": True}
                    return ctx, None
                except RemoteError:
                    pass
            problems.append(opnsense.error_text(exc, key, secret) if two else unraid.error_text(exc, key))
            return ctx, None
        if two:
            ctx["result"] = {"ok": result.ok, "problem": result.problem, "roles": [], "key_name": "", "warnings": [],
                             "facts": _facts_opnsense(result) if result.ok else [], "sources": result.sources}
        else:
            ctx["result"] = {"ok": result.ok, "problem": result.problem, "roles": result.roles, "key_name": result.key_name,
                             "facts": _facts(result) if result.ok else [], "warnings": result.warnings, "sources": []}
        if action != "save" or not result.ok:
            return ctx, None
        # --- Save
        fp = fingerprint(pem) if tls == "pin" else None
        try:
            if existing is None:
                store.add(conn, cfg.data_dir, form["name"], kind, url, key, tls=tls, pin=fp, cert=pem,
                          interval=interval, secret=secret)
                log.info("System %s (%s) added from %s", form["name"], kind, client(request))
                flash(request, f"Added {form['name']}. The first read happens within a few seconds.")
            else:
                store.update(conn, cfg.data_dir, existing["id"], url=url, tls=tls, pin=fp, cert=pem, interval=interval,
                             enabled=form["enabled"], key=key if key_new else None, secret=secret if key_new else None)
                if not form["enabled"]:
                    poll._set_unreachable(conn, store.get(conn, existing["id"]), time.time(), None)
                log.info("System %s updated from %s", existing["id"], client(request))
                flash(request, f"Saved {existing['id']}" + ("" if form["enabled"] else " (disabled)") + ".")
        except ValueError as exc:
            problems.append(str(exc))
            return ctx, None
        pending.drop(form["pending"])
        return ctx, RedirectResponse("/", status_code=303)

    def read_form(kind, name, url, key, tls, pin_confirm, trust, interval, pending_token, enabled, secret="") -> dict:
        # "trust" is the button next to a fingerprint: it confirms exactly the fingerprint that was shown.
        return {"kind": kind[:20], "name": name.strip()[:80], "url": url.strip()[:300], "key": key[:300], "secret": secret[:300],
                "tls": tls[:10], "pin_confirm": (trust or pin_confirm)[:120], "interval": interval[:8],
                "pending": pending_token[:60], "enabled": enabled != ""}

    @app.get("/remotes/new")
    async def new_form(request: Request, kind: str = "unraid"):
        require_login(request)
        f = blank()
        f["kind"] = kind if kind in store.KINDS else "unraid"
        return page(request, {"f": f, "existing": None, "problems": [], "result": None, "cert": None,
                              "KINDS": store.KINDS, "GUIDES": store.GUIDES})

    @app.post("/remotes/new")
    async def new_post(request: Request, kind: str = Form("unraid"), name: str = Form(""), url: str = Form(""),
                       key: str = Form(""), secret: str = Form(""), tls: str = Form("verify"), pin_confirm: str = Form(""),
                       trust: str = Form(""), interval: str = Form("60"),
                       pending_token: str = Form("", alias="pending"), action: str = Form("test")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        form = read_form(kind, name, url, key, tls, pin_confirm, trust, interval, pending_token, "on", secret)
        ctx, redirect = await work(request, form, None, action)
        return redirect or page(request, ctx, 400 if ctx["problems"] else 200)

    def existing_or_404(remote_id: str):
        row = store.get(conn, remote_id) if hub.HOST_RE.match(remote_id) else None
        if row is None:
            raise HTTPException(404)
        return row

    @app.get("/remotes/{remote_id}/edit")
    async def edit_form(request: Request, remote_id: str):
        require_login(request)
        row = existing_or_404(remote_id)
        return page(request, {"f": blank(row), "existing": row, "problems": [], "result": None, "cert": None,
                              "KINDS": store.KINDS, "GUIDES": store.GUIDES})

    @app.post("/remotes/{remote_id}/edit")
    async def edit_post(request: Request, remote_id: str, url: str = Form(""), key: str = Form(""),
                        secret: str = Form(""), tls: str = Form("verify"), pin_confirm: str = Form(""), trust: str = Form(""),
                        interval: str = Form("60"), pending_token: str = Form("", alias="pending"),
                        enabled: str = Form(""), action: str = Form("test")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        row = existing_or_404(remote_id)
        form = read_form(row["kind"], row["id"], url, key, tls, pin_confirm, trust, interval, pending_token, enabled, secret)
        ctx, redirect = await work(request, form, row, action)
        return redirect or page(request, ctx, 400 if ctx["problems"] else 200)

    @app.post("/remotes/{remote_id}/toggle")
    async def toggle(request: Request, remote_id: str, enable: str = Form("")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        row = existing_or_404(remote_id)
        on = enable == "1"
        store.set_enabled(conn, remote_id, on)
        if not on:
            poll._set_unreachable(conn, store.get(conn, remote_id), time.time(), None)
        log.info("System %s %s from %s", remote_id, "enabled" if on else "disabled", client(request))
        flash(request, f"{row['id']} {'enabled' if on else 'disabled'}.")
        return RedirectResponse("/", status_code=303)

    @app.post("/remotes/{remote_id}/remove")
    async def remove(request: Request, remote_id: str, confirm: str = Form("")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        row = existing_or_404(remote_id)
        if confirm.strip() != row["id"]:
            flash(request, f"To remove {row['id']}, type its name to confirm.", error=True)
            return RedirectResponse(f"/remotes/{row['id']}/edit", status_code=303)
        store.remove(conn, cfg.data_dir, row["id"], purge=True)
        log.info("System %s removed from %s", remote_id, client(request))
        flash(request, f"Removed {row['id']}: its API key file and its history are deleted.")
        return RedirectResponse("/", status_code=303)


    @app.post("/h/{host}/roles")
    async def set_roles(request: Request, host: str):
        """Save the owner's interface roles for a firewall (stored in the hub, never sent to the firewall) and
        re-check its findings at once. Fields are `role-<interface id>` with `auto` or a role."""
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        row = existing_or_404(host)
        if row["kind"] != "opnsense":
            raise HTTPException(404)
        form = await request.form()
        snap = db.get_snapshot(conn, host, "opnsense_interfaces")
        known = {i["id"] for i in ((snap.data or {}).get("interfaces", []) if snap and snap.data else []) if i.get("id")}
        chosen = {k[5:]: str(v) for k, v in form.items() if k.startswith("role-") and k[5:] in known}
        overrides = {k: v for k, v in chosen.items() if v in roles.ROLES}
        # An override equal to what DaemonSight works out on its own is the same as no override.
        data = {name.removeprefix(opnsense.SNAPSHOT_PREFIX): (s.data if (s := db.get_snapshot(conn, host, name)) and s.data
                                                              and s.data.get("available") is not False else None)
                for name in opnsense.SOURCES}
        auto = opnsense_rules_roles(data)
        overrides = {k: v for k, v in overrides.items() if auto.get(k) != v}
        before = roles.load_overrides(conn, host)
        by = str(request.session.get("user") or "admin")
        if overrides != before:
            roles.save_overrides(conn, host, overrides)
            changes = sorted(f"{k}: {v}" for k, v in overrides.items())
            db.add_event(conn, host, time.time(), "setting", "Interface roles changed",
                         detail=(f"by {by}: " + ("; ".join(changes) if changes else "all automatic")))
            poll.reconcile(conn, host, "opnsense", time.time())
            log.info("Interface roles of %s changed by %s from %s", host, by, client(request))
            flash(request, "Interface roles saved. The findings are re-checked.")
        else:
            flash(request, "No changes: those roles are already in effect.")
        return RedirectResponse(f"/h/{host}/network#interfaces", status_code=303)
