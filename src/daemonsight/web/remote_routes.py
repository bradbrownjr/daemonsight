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
from ..remote import crowdsec, docker_storage, opnsense, poll, roles, store, unifi, unraid
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
    pending_reader = Pending()          # the Docker reader's token, typed and not yet saved (memory only)
    pending_crowdsec = Pending()        # the CrowdSec bouncer key, the same

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
        return render(request, "remote_form.html", {"page": "remotes", "v": {"host": None}, "last": last,
                                                    "crowdsec_result": None, **ctx}, status)

    def blank(existing=None) -> dict:
        return {"kind": existing["kind"] if existing else "unraid", "name": existing["id"] if existing else "",
                "url": existing["url"] if existing else "",
                "tls": existing["tls"] if existing else "verify",
                "pin_confirm": fmt_fingerprint(existing["tls_pin"]) if existing and existing["tls_pin"] else "",
                "interval": existing["interval"] if existing else store.DEFAULT_INTERVAL,
                "enabled": bool(existing["enabled"]) if existing else True, "pending": "",
                "reader_on": bool(existing["reader_url"]) if existing else False,
                "reader_url": (existing["reader_url"] or "") if existing else "", "pending_reader": "",
                "reader_token_saved": bool(existing and store.read_reader_token(cfg.data_dir, existing["id"])),
                "crowdsec_on": bool(existing["crowdsec_url"]) if existing else False,
                "crowdsec_url": (existing["crowdsec_url"] or "") if existing else "", "pending_crowdsec": "",
                "crowdsec_never": "\n".join(store.never_list(existing)) if existing else "",
                "crowdsec_key_saved": bool(existing and store.read_crowdsec_key(cfg.data_dir, existing["id"]))}

    async def work(request: Request, form: dict, existing, action: str):
        """Check the form, look at the server, and (on Save) store it. Returns
        (context for the page, redirect or None)."""
        ctx = {"f": form, "existing": existing, "problems": [], "result": None, "cert": None, "KINDS": store.KINDS, "GUIDES": store.GUIDES,
               "reader_result": None}
        problems = ctx["problems"]
        typed_reader_token = form.pop("reader_token", "")
        form["reader_token_saved"] = bool(existing and store.read_reader_token(cfg.data_dir, existing["id"]))
        typed_cs_key = form.pop("crowdsec_key", "")
        form["crowdsec_key_saved"] = bool(existing and store.read_crowdsec_key(cfg.data_dir, existing["id"]))
        # --- the fields
        kind = existing["kind"] if existing is not None else form["kind"]
        if kind not in store.KINDS:
            problems.append("Pick the kind of system.")
            return ctx, None
        two = kind in store.TWO_PART
        form["kind"] = kind
        # --- the Docker reader (Unraid only): an address and a token, a dependent option of the same form
        reader_url, reader_token, reader_new = None, None, False
        if kind == "unraid" and form["reader_on"]:
            try:
                reader_url = docker_storage.normalize_url(form["reader_url"])
                form["reader_url"] = reader_url
            except ValueError as exc:
                problems.append(f"Docker reader address: {exc}")
            if typed_reader_token.strip():
                try:
                    reader_token, reader_new = store.clean_reader_token(typed_reader_token), True
                except ValueError as exc:
                    problems.append(f"Docker reader token: {exc}")
            elif (held := pending_reader.get(form["pending_reader"])) is not None:
                reader_token, reader_new = held, True
            elif existing is not None:
                reader_token = store.read_reader_token(cfg.data_dir, existing["id"])
            if reader_token is None and not any(p.startswith("Docker reader token") for p in problems):
                problems.append("Docker reader token: enter the token from the reader's token file.")
            if reader_token is not None and reader_new:
                form["pending_reader"] = pending_reader.put(reader_token, form["pending_reader"] or None)
        # --- CrowdSec bans (OPNsense only): the Local API's address, a bouncer key and a never-ban list, a dependent
        # option of the same form
        cs_url, cs_key, cs_new, cs_never = None, None, False, []
        if kind == "opnsense" and form["crowdsec_on"]:
            try:
                cs_url = crowdsec.normalize_url(form["crowdsec_url"])
                form["crowdsec_url"] = cs_url
            except ValueError as exc:
                problems.append(f"CrowdSec address: {exc}")
            if typed_cs_key.strip():
                try:
                    cs_key, cs_new = store.clean_crowdsec_key(typed_cs_key), True
                except ValueError as exc:
                    problems.append(f"CrowdSec key: {exc}")
            elif (held := pending_crowdsec.get(form["pending_crowdsec"])) is not None:
                cs_key, cs_new = held, True
            elif existing is not None:
                cs_key = store.read_crowdsec_key(cfg.data_dir, existing["id"])
            if cs_key is None and not any(p.startswith("CrowdSec key") for p in problems):
                problems.append("CrowdSec key: enter the key that cscli bouncers add printed.")
            if cs_key is not None and cs_new:
                form["pending_crowdsec"] = pending_crowdsec.put(cs_key, form["pending_crowdsec"] or None)
            try:
                cs_never = store.clean_never_list(form["crowdsec_never"])
                form["crowdsec_never"] = "\n".join(cs_never)
            except ValueError as exc:
                problems.append(f"Never-ban list: {exc}")
        if action == "test-crowdsec":
            if kind != "opnsense" or not form["crowdsec_on"]:
                problems.append("Tick Read CrowdSec bans first.")
            elif cs_url is not None and cs_key is not None:
                try:
                    await crowdsec.probe(net, cs_url, cs_key)
                    ctx["crowdsec_result"] = {"ok": True}
                except RemoteError as exc:
                    problems.append("CrowdSec: " + crowdsec.error_text(exc, cs_key))
            return ctx, None
        if action == "test-reader":
            if kind != "unraid" or not form["reader_on"]:
                problems.append("Tick Read images and volumes first.")
            elif reader_url is not None and reader_token is not None:
                try:
                    r = await docker_storage.probe(net, reader_url, reader_token)
                    ctx["reader_result"] = {"ok": True, "docker": r.docker, "api": r.api}
                except RemoteError as exc:
                    problems.append("Docker reader: " + docker_storage.error_text(exc, reader_token))
            return ctx, None
        if existing is None:
            if not form["name"]:
                problems.append("Name: type a name for this system, e.g. firewall (the grey text is only an example).")
            elif not hub.HOST_RE.match(form["name"]):
                problems.append("Name: use letters, digits, '.', '_' and '-', starting with a letter or digit (63 at most); "
                                "no spaces.")
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
            if kind == "unifi":
                result = await unifi.probe(net, url, key, tls, pem)
            else:
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
            # The message is already scrubbed of the key; the path says which call failed.
            log.info("Test of %s (%s) failed: %s [%s] %s", form["name"] or "new system", kind, exc.kind,
                     getattr(exc, "path", None) or "-", str(exc)[:200])
            problems.append(opnsense.error_text(exc, key, secret) if two else
                            unifi.error_text(exc, key) if kind == "unifi" else unraid.error_text(exc, key))
            return ctx, None
        if kind == "unifi":
            ctx["result"] = {"ok": result.ok, "problem": result.problem, "roles": [], "key_name": "", "warnings": [],
                             "facts": list(result.facts) if result.ok else [], "sources": result.sources, "note": result.note}
        elif two:
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
                          interval=interval, secret=secret, reader_url=reader_url,
                          reader_token=reader_token if reader_url else None, crowdsec_url=cs_url,
                          crowdsec_key=cs_key if cs_url else None, crowdsec_never=cs_never)
                log.info("System %s (%s) added from %s", form["name"], kind, client(request))
                db.add_event(conn, db.HUB_HOST, time.time(), "setting", f"System added: {form['name']}",
                             detail=f"by {request.session.get('user') or 'admin'}; read over its {kind} API")
                flash(request, f"Added {form['name']}. The first read happens within a few seconds.")
            else:
                reader_arg = None if (reader_url is None and not existing["reader_url"]) else \
                    (reader_url, reader_token if reader_new else None)
                cs_arg = None if (cs_url is None and not existing["crowdsec_url"]) else \
                    (cs_url, cs_key if cs_new else None, cs_never)
                store.update(conn, cfg.data_dir, existing["id"], url=url, tls=tls, pin=fp, cert=pem, interval=interval,
                             enabled=form["enabled"], key=key if key_new else None, secret=secret if key_new else None,
                             reader=reader_arg, crowdsec=cs_arg)
                if not form["enabled"]:
                    poll._set_unreachable(conn, store.get(conn, existing["id"]), time.time(), None)
                log.info("System %s updated from %s", existing["id"], client(request))
                flash(request, f"Saved {existing['id']}" + ("" if form["enabled"] else " (disabled)") + ".")
        except ValueError as exc:
            problems.append(str(exc))
            return ctx, None
        pending.drop(form["pending"])
        pending_reader.drop(form["pending_reader"])
        pending_crowdsec.drop(form["pending_crowdsec"])
        return ctx, RedirectResponse("/", status_code=303)

    def read_form(kind, name, url, key, tls, pin_confirm, trust, interval, pending_token, enabled, secret="",
                  reader_on="", reader_url="", reader_token="", pending_reader_token="", crowdsec_on="", crowdsec_url="",
                  crowdsec_key="", crowdsec_never="", pending_crowdsec_key="") -> dict:
        # "trust" is the button next to a fingerprint: it confirms exactly the fingerprint that was shown.
        return {"kind": kind[:20], "name": name.strip()[:80], "url": url.strip()[:300], "key": key[:300], "secret": secret[:300],
                "tls": tls[:10], "pin_confirm": (trust or pin_confirm)[:120], "interval": interval[:8],
                "pending": pending_token[:60], "enabled": enabled != "", "reader_on": reader_on != "",
                "reader_url": reader_url.strip()[:300], "reader_token": reader_token[:300],
                "pending_reader": pending_reader_token[:60], "crowdsec_on": crowdsec_on != "",
                "crowdsec_url": crowdsec_url.strip()[:300], "crowdsec_key": crowdsec_key[:300],
                "crowdsec_never": crowdsec_never[:4000], "pending_crowdsec": pending_crowdsec_key[:60]}

    @app.get("/remotes/new")
    async def new_form(request: Request, kind: str = "unraid"):
        require_login(request)
        f = blank()
        f["kind"] = kind if kind in store.KINDS else "unraid"
        return page(request, {"f": f, "existing": None, "problems": [], "result": None, "cert": None,
                              "KINDS": store.KINDS, "GUIDES": store.GUIDES, "reader_result": None})

    @app.post("/remotes/new")
    async def new_post(request: Request, kind: str = Form("unraid"), name: str = Form(""), url: str = Form(""),
                       key: str = Form(""), secret: str = Form(""), tls: str = Form("verify"), pin_confirm: str = Form(""),
                       trust: str = Form(""), interval: str = Form("60"),
                       pending_token: str = Form("", alias="pending"), action: str = Form("test"),
                       reader_on: str = Form(""), reader_url: str = Form(""), reader_token: str = Form(""),
                       pending_reader_token: str = Form("", alias="pending_reader"), crowdsec_on: str = Form(""),
                       crowdsec_url: str = Form(""), crowdsec_key: str = Form(""), crowdsec_never: str = Form(""),
                       pending_crowdsec_key: str = Form("", alias="pending_crowdsec")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        form = read_form(kind, name, url, key, tls, pin_confirm, trust, interval, pending_token, "on", secret,
                         reader_on, reader_url, reader_token, pending_reader_token, crowdsec_on, crowdsec_url,
                         crowdsec_key, crowdsec_never, pending_crowdsec_key)
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
                              "KINDS": store.KINDS, "GUIDES": store.GUIDES, "reader_result": None})

    @app.post("/remotes/{remote_id}/edit")
    async def edit_post(request: Request, remote_id: str, url: str = Form(""), key: str = Form(""),
                        secret: str = Form(""), tls: str = Form("verify"), pin_confirm: str = Form(""), trust: str = Form(""),
                        interval: str = Form("60"), pending_token: str = Form("", alias="pending"),
                        enabled: str = Form(""), action: str = Form("test"), reader_on: str = Form(""),
                        reader_url: str = Form(""), reader_token: str = Form(""),
                        pending_reader_token: str = Form("", alias="pending_reader"), crowdsec_on: str = Form(""),
                        crowdsec_url: str = Form(""), crowdsec_key: str = Form(""), crowdsec_never: str = Form(""),
                        pending_crowdsec_key: str = Form("", alias="pending_crowdsec")):
        try:
            post_guard(request)
        except HTTPException as exc:
            if exc.status_code == 403:
                return PlainTextResponse(exc.detail, status_code=403)
            raise
        row = existing_or_404(remote_id)
        form = read_form(row["kind"], row["id"], url, key, tls, pin_confirm, trust, interval, pending_token, enabled, secret,
                         reader_on, reader_url, reader_token, pending_reader_token, crowdsec_on, crowdsec_url,
                         crowdsec_key, crowdsec_never, pending_crowdsec_key)
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
        db.add_event(conn, db.HUB_HOST, time.time(), "setting", f"System removed: {row['id']}",
                     detail=f"by {request.session.get('user') or 'admin'}; its API key file and history are deleted")
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
            poll.reconcile(conn, host, "opnsense", time.time(), cfg)
            log.info("Interface roles of %s changed by %s from %s", host, by, client(request))
            flash(request, "Interface roles saved. The findings are re-checked.")
        else:
            flash(request, "No changes: those roles are already in effect.")
        return RedirectResponse(f"/h/{host}/network#interfaces", status_code=303)
