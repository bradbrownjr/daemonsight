"""The web UI. It never touches sockets, logs or tools, only the database.
On a host it opens the database read-only. On a hub it also writes what
collectors upload (see add_ingest)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import sqlite3
import time
import unicodedata
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import config as config_mod, db, full_version, hub, settings, shodan
from ..config import Config
from ..remote.client import Net
from . import opnsense_views, report, unraid_views, views
from .auth import PasswordStore, RateLimiter

log = logging.getLogger("daemonsight.auth")
HERE = Path(__file__).parent

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class LoginRequired(Exception):
    pass


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


def create_app(cfg: Config, *, secret: str | None = None, config_file: Path | None = None,
               cve_client=None, remote_net: Net | None = None, outside_client=None) -> FastAPI:
    if secret is None:
        secret = Path(cfg.web.secret_file).read_text().strip()
    if len(secret) < 32:
        raise RuntimeError(f"session secret in {cfg.web.secret_file} is too short")

    hub_conn = db.connect_writer(cfg.db_path) if cfg.hub.enabled else None
    net = remote_net or Net()

    @asynccontextmanager
    async def lifespan(_app):
        tasks = []
        if hub_conn is not None:
            # Every chore runs for the life of the hub and reads its settings again on each pass (a change on
            # the Settings page applies at the next one, with no restart). A chore that is switched off does
            # nothing, and closes the findings it left behind.
            from .. import outside as outside_chore
            from ..cve import run as cve_run
            from ..remote import poll as remote_poll
            tasks.append(asyncio.create_task(_hub_chores(hub_conn, cfg, config_file)))
            tasks.append(asyncio.create_task(cve_run.loop(cfg, hub_conn, cve_client)))
            tasks.append(asyncio.create_task(outside_chore.loop(cfg, hub_conn, outside_client)))
            tasks.append(asyncio.create_task(remote_poll.loop(cfg, hub_conn, net)))
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware, secret_key=secret, session_cookie="daemonsight_session",
        max_age=cfg.web.session_hours * 3600, same_site="strict", https_only=cfg.web.secure_cookies,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["version"] = full_version()

    passwords = PasswordStore(cfg.web.password_file)
    limiter = RateLimiter()

    @contextmanager
    def reader():
        try:
            conn = db.connect_reader(cfg.db_path)
        except (FileNotFoundError, sqlite3.OperationalError):
            yield None
            return
        try:
            yield conn
        finally:
            conn.close()

    def password_mark() -> str | None:
        """A keyed fingerprint of the current password hash. A session stores
        it at login and must still match, so changing the password ends every
        session. Keyed with the session secret so the cookie reveals nothing
        about the hash."""
        stored = passwords.current_hash()
        if not stored:
            return None
        return hmac.new(secret.encode(), stored.encode(), hashlib.sha256).hexdigest()

    def require_login(request: Request) -> None:
        mark = password_mark()
        if (request.session.get("user") != "admin" or mark is None
                or not hmac.compare_digest(str(request.session.get("pw", "")), mark)):
            raise LoginRequired()

    def theme_pref(request: Request) -> str:
        """What the reader chose: light, dark or auto (follow the system). Dark until they choose."""
        value = request.cookies.get("theme")
        return value if value in ("light", "dark", "auto") else "dark"

    def theme(request: Request) -> str:
        """The theme to render: auto starts dark and /static/theme.js corrects it before the page paints."""
        return "light" if theme_pref(request) == "light" else "dark"

    def live(conn) -> Config:
        """The config file's values with the Settings page's applied (a hub only: any other install has none)."""
        return settings.effective(cfg, conn) if cfg.hub.enabled else cfg

    def flash(request: Request, text: str, error: bool = False) -> None:
        """A one-line notice for the next full page (never a partial refresh)."""
        request.session["flash"] = {"text": text, "error": error}

    def render(request: Request, name: str, ctx: dict, status: int = 200) -> HTMLResponse:
        notice = None if name.startswith("partials/") else request.session.pop("flash", None)
        # Accepting a finding writes to the database; only a hub's web process may.
        ctx = {"theme": theme(request), "theme_pref": theme_pref(request), "path": request.url.path, "base": "", "hub": cfg.hub.enabled,
               "can_accept": cfg.hub.enabled, "flash": notice, **ctx}
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    @app.exception_handler(LoginRequired)
    async def to_login(request: Request, exc: LoginRequired):
        if request.headers.get("HX-Request"):
            return Response(status_code=200, headers={"HX-Redirect": "/login"})
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz():
        return "ok"

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request, next: str = "/"):
        return render(request, "login.html", {"next": _safe_next(next), "error": None,
                                              "no_password": passwords.current_hash() is None})

    @app.post("/login")
    async def login(request: Request, password: str = Form(""), next: str = Form("/")):
        client = request.client.host if request.client else "unknown"
        if limiter.blocked(client):
            log.warning("Failed login from %s (rate limited)", client)
            return render(request, "login.html", {"next": _safe_next(next), "no_password": False,
                                                  "error": "Too many attempts. Wait a few minutes."}, 429)
        if not passwords.verify(password):
            limiter.fail(client)
            log.warning("Failed login from %s", client)
            return render(request, "login.html", {"next": _safe_next(next),
                                                  "no_password": passwords.current_hash() is None,
                                                  "error": "Wrong password."}, 401)
        limiter.reset(client)
        request.session.clear()
        request.session["user"] = "admin"
        request.session["pw"] = password_mark()
        log.info("Login from %s", client)
        return RedirectResponse(_safe_next(next), status_code=303)

    @app.post("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.post("/theme")
    async def set_theme(request: Request, next: str = Form("/"), theme_choice: str = Form("", alias="theme")):
        """Set the theme to light, dark or auto; with no choice, switch between light and dark."""
        require_login(request)
        response = RedirectResponse(_safe_next(next), status_code=303)
        new = theme_choice if theme_choice in ("light", "dark", "auto") else \
            ("dark" if theme(request) == "light" else "light")
        response.set_cookie("theme", new, max_age=365 * 86400, samesite="strict",
                            secure=cfg.web.secure_cookies, httponly=True)
        return response

    # --- the Settings page ------------------------------------------------------
    # Everyone sees it. On a hub, the hub's web process (the database's one writer) saves changes to the
    # `settings` table; they sit over the config file and apply at each chore's next pass. On a single host
    # the page shows the effective values read-only, since that web process opens the database read-only.
    # What controls login or where the server listens is never editable here (settings.READ_ONLY).
    file_path = config_file or config_mod.config_path()
    can_edit = cfg.hub.enabled

    def settings_page(request: Request, conn, status: int = 200, errors: dict | None = None,
                      posted: dict | None = None, problems: list | None = None) -> HTMLResponse:
        groups = settings.describe(cfg, conn, can_edit)
        events = views.events_list(conn, db.HUB_HOST, 20) if conn is not None and can_edit else []
        ctx = {"groups": groups, "read_only": settings.read_only(live(conn) if conn is not None else cfg),
               "shodan": {"saved": shodan.key_saved(cfg), "path": str(cfg.shodan_key_path)},
               "can_edit": can_edit, "config_path": str(file_path), "errors": errors or {},
               "posted": posted or {}, "problems": problems or [], "events": events, "no_filter": True, "host": None}
        return render(request, "settings.html", {"page": "settings", "v": ctx}, status)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_get(request: Request):
        require_login(request)
        with reader() as conn:
            return settings_page(request, conn)

    def _origin(key: str) -> str:
        f = settings.BY_KEY[key]
        return "config file" if settings.source_of(cfg, f, {}) == settings.FILE else "default"

    if cfg.hub.enabled:
        @app.post("/settings")
        async def settings_post(request: Request):
            """Save the settings of one group, or reset one. Everything is checked first and nothing is
            written unless all of it is valid; a key that isn't an editable setting (the listen port, the
            password file, ...) refuses the whole request, whoever sent it."""
            require_login(request)
            if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return PlainTextResponse("cross-site request refused", status_code=403)
            form = await request.form()
            items = [(k, v) for k, v in form.multi_items() if isinstance(v, str)]
            by = str(request.session.get("user") or "admin")
            client = request.client.host if request.client else "?"
            # The Shodan key box sits in the Outside view form, so its key arrives with the group. It is
            # taken out here and written to its own file, never to the settings table.
            typed_key = next((v for k, v in items if k == "shodan_key"), "").strip()
            items = [(k, v) for k, v in items if k != "shodan_key"]
            refused = [k for k, _ in items if k not in settings.BY_KEY and k not in ("group", "reset")]
            resets = [v for k, v in items if k == "reset"]
            if resets and (len(resets) > 1 or resets[0] not in settings.BY_KEY):
                refused.append(resets[0][:60])
            if refused:
                fixed = {x[0] for x in settings.READ_ONLY}
                problems = [f"{k[:60]} can't be changed on this page. It is set in the config file "
                            f"({file_path}) and needs a restart." if k in fixed else f"{k[:60]} is not a setting."
                            for k in refused]
                with reader() as conn:
                    return settings_page(request, conn, 400, problems=problems)
            if resets:
                key = resets[0]
                f = settings.BY_KEY[key]
                if settings.reset(hub_conn, cfg, key, by):
                    log.info("Setting %s reset by %s from %s", key, by, client)
                    flash(request, f"Reset: {f.name}. It now follows the {_origin(key)}.")
                else:
                    flash(request, f"{f.name} was not set here; nothing to reset.", error=True)
                return RedirectResponse(f"/settings#{f.group}", status_code=303)
            values, errors = {}, {}
            posted = {k: v for k, v in items if k in settings.BY_KEY}
            for key, raw in posted.items():
                try:
                    values[key] = settings.parse(settings.BY_KEY[key], raw)
                except settings.Invalid as exc:
                    errors[key] = str(exc)
            if typed_key:
                try:
                    typed_key = shodan.clean_key(typed_key)
                except ValueError as exc:
                    errors["outside.source"] = str(exc)
            if values.get("outside.source") == "shodan" and not typed_key and not shodan.key_saved(cfg):
                errors["outside.source"] = "No Shodan API key is saved. Paste your key under Source, then save."
            if errors:
                with reader() as conn:
                    return settings_page(request, conn, 400, errors=errors, posted=posted)
            key_saved = False
            if typed_key:
                try:
                    shodan.write_key(cfg, typed_key)
                except OSError as exc:
                    log.error("Could not save the Shodan API key: %s", exc.strerror or type(exc).__name__)
                    flash(request, "Nothing was saved: the key file could not be written. Check the data folder's "
                                   "permissions.", error=True)
                    return RedirectResponse("/settings#outside", status_code=303)
                db.add_event(hub_conn, db.HUB_HOST, time.time(), "setting", "Shodan API key saved", detail=f"by {by}")
                log.info("Shodan API key saved by %s from %s", by, client)
                key_saved = True
            changed = settings.save(hub_conn, cfg, values, by)
            for key in changed:
                log.info("Setting %s changed by %s from %s", key, by, client)
            group = next((k.split(".")[0] for k in posted), "")
            if changed or key_saved:
                names = [settings.BY_KEY[k].name for k in changed] + (["Shodan API key"] if key_saved else [])
                flash(request, "Saved: " + "; ".join(names) + ". It applies at the next pass of the chore that uses it.")
            else:
                flash(request, "No changes: those values are already in effect.")
            return RedirectResponse(f"/settings#{group}" if group else "/settings", status_code=303)

        @app.post("/settings/shodan-key")
        async def shodan_key_post(request: Request, key: str = Form(""), shodan_key: str = Form(""),
                                  action: str = Form("")):
            """Save, replace, remove or test the Shodan API key. The key is typed here once and written to a 0600
            file; it is never put into a page, an event, a log line or the database, and these routes never show
            it. Test uses the key typed in the box, else the saved one, and shows Shodan's plan and credits or
            its error. Needs the login and refuses a cross-site request, like every hub action."""
            require_login(request)
            if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return PlainTextResponse("cross-site request refused", status_code=403)
            by = str(request.session.get("user") or "admin")
            client = request.client.host if request.client else "?"
            back = RedirectResponse("/settings#outside", status_code=303)
            typed = (key or shodan_key).strip()   # shodan_key: the box in the Outside view form
            if action == "save":
                try:
                    shodan.write_key(cfg, typed)
                except ValueError as exc:
                    flash(request, str(exc), error=True)
                    return back
                except OSError as exc:
                    log.error("Could not save the Shodan API key: %s", exc.strerror or type(exc).__name__)
                    flash(request, "The key file could not be written. Check the data folder's permissions.", error=True)
                    return back
                db.add_event(hub_conn, db.HUB_HOST, time.time(), "setting", "Shodan API key saved", detail=f"by {by}")
                log.info("Shodan API key saved by %s from %s", by, client)
                flash(request, "Shodan API key saved. Press Test key to check it, then set Source to Shodan API.")
            elif action == "remove":
                if settings.effective(cfg, hub_conn).outside.source == "shodan":
                    flash(request, "The Shodan API is the chosen source. Set Source back to InternetDB and save "
                                   "before you remove the key.", error=True)
                elif shodan.delete_key(cfg):
                    db.add_event(hub_conn, db.HUB_HOST, time.time(), "setting", "Shodan API key removed",
                                 detail=f"by {by}")
                    log.info("Shodan API key removed by %s from %s", by, client)
                    flash(request, "Shodan API key removed. The key file is deleted.")
                else:
                    flash(request, "No Shodan API key was saved.", error=True)
            elif action == "test":
                use = typed
                if use:
                    try:
                        use = shodan.clean_key(use)
                    except ValueError as exc:
                        flash(request, str(exc), error=True)
                        return back
                else:
                    use = shodan.read_key(cfg) or ""
                if not use:
                    flash(request, "Enter a key to test, or save one first.", error=True)
                    return back
                own = outside_client is None
                http = outside_client or httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=False)
                try:
                    info = await shodan.api_info(http, use)
                finally:
                    if own:
                        await http.aclose()
                text = shodan.describe_info(info)
                if info.ok and typed:
                    text += " This key is not saved yet: press Save key to keep it."
                flash(request, text, error=not info.ok)
                log.info("Shodan API key tested by %s from %s: %s", by, client, "accepted" if info.ok else "not accepted")
            else:
                flash(request, "Unknown action.", error=True)
            return back

    # --- pages ---------------------------------------------------------------
    # On a single host the pages live at /, /exposure ... for this host. On a
    # hub, / lists the hosts and each host's pages live under /h/<host>/.
    KIND_PAGES = {"unraid": unraid_views.PAGE_FUNCS, "opnsense": opnsense_views.PAGE_FUNCS}
    KIND_TEMPLATE_PREFIX = {"unraid": "unraid_", "opnsense": "opn_"}
    pages = {"overview": views.overview, "exposure": views.exposure, "routes": views.routes,
             "services": views.services, "fail2ban": views.jails, "packages": views.packages,
             "vulnerabilities": views.vulnerabilities}

    def resolve(conn, host: str | None) -> tuple[Config, str]:
        if not cfg.hub.enabled:
            return cfg, ""
        if host is None or not hub.HOST_RE.match(host) or \
                not conn.execute("SELECT 1 FROM hosts WHERE id = ?", (host,)).fetchone():
            raise HTTPException(404)
        return views.host_config(conn, live(conn), host), f"/h/{host}"

    async def show(request: Request, name: str, host: str | None, partial: bool, units: str = "active"):
        require_login(request)
        tname = name
        with reader() as conn:
            if conn is None:
                if cfg.hub.enabled:
                    raise HTTPException(404)
                ctx, base = None, ""
            else:
                hcfg, base = resolve(conn, host)
                if hcfg.kind:
                    # A system the hub reads over its API has its own pages, by kind.
                    funcs = KIND_PAGES.get(hcfg.kind, {})
                    if name not in funcs:
                        raise HTTPException(404)
                    ctx = funcs[name](conn, hcfg)
                    tname = name if name == "overview" else f"{KIND_TEMPLATE_PREFIX[hcfg.kind]}{name}"
                elif name not in pages:
                    raise HTTPException(404)
                elif name == "services":
                    ctx = views.services(conn, hcfg, units if units in views.UNIT_FILTERS else "active")
                else:
                    ctx = pages[name](conn, hcfg)
        template = f"partials/{tname}.html" if partial else f"{tname}.html"
        return render(request, template, {"page": name, "v": ctx, "base": base})

    async def logs(request: Request, cname: str, host: str | None = None):
        require_login(request)
        with reader() as conn:
            if conn is None:
                ctx, base = None, ""
            else:
                hcfg, base = resolve(conn, host)
                if hcfg.kind:
                    raise HTTPException(404)
                ctx = views.container_logs(conn, hcfg, cname)
        return render(request, "partials/logs.html", {"logs": ctx, "name": cname, "base": base})

    async def report_page(request: Request, host: str | None = None):
        require_login(request)
        with reader() as conn:
            if conn is None:
                if cfg.hub.enabled:
                    raise HTTPException(404)
                ctx, base = None, ""
            else:
                hcfg, base = resolve(conn, host)
                ctx = report.build(conn, hcfg, base)
        return render(request, "report.html", {"page": "report", "v": ctx, "base": base})

    async def report_markdown(request: Request, host: str | None = None):
        require_login(request)
        with reader() as conn:
            if conn is None:
                raise HTTPException(404)
            hcfg, base = resolve(conn, host)
            now = time.time()
            rep = report.build(conn, hcfg, base, now)
        return Response(rep["markdown"], media_type="text/markdown; charset=utf-8", headers={
            "Content-Disposition": f"attachment; filename={report.filename(hcfg.host_id, now)}"})

    def handler(name: str, partial: bool):
        async def route(request: Request, host: str | None = None, units: str = "active"):
            return await show(request, name, host, partial, units)
        return route

    def add_pages(prefix: str) -> None:
        for name in pages:
            path = "/" if name == "overview" else f"/{name}"
            app.add_api_route(prefix + path, handler(name, False), methods=["GET"], response_class=HTMLResponse)
            app.add_api_route(f"{prefix}/partials/{name}", handler(name, True), methods=["GET"],
                              response_class=HTMLResponse)
        app.add_api_route(prefix + "/partials/logs/{cname}", logs, methods=["GET"], response_class=HTMLResponse)
        app.add_api_route(prefix + "/report", report_page, methods=["GET"], response_class=HTMLResponse)
        app.add_api_route(prefix + "/report.md", report_markdown, methods=["GET"])

    if cfg.hub.enabled:
        add_pages("/h/{host}")
        # the other pages the systems read over an API have (Unraid's, then OPNsense's)
        for name in dict.fromkeys(unraid_views.PAGES[1:] + opnsense_views.PAGES[1:]):
            app.add_api_route(f"/h/{{host}}/{name}", handler(name, False), methods=["GET"], response_class=HTMLResponse)
            app.add_api_route(f"/h/{{host}}/partials/{name}", handler(name, True), methods=["GET"],
                              response_class=HTMLResponse)
        from .remote_routes import add_remote_routes
        add_remote_routes(app, cfg, hub_conn, render=render, require_login=require_login, flash=flash, net=net)

        @app.get("/", response_class=HTMLResponse)
        async def hosts_page(request: Request):
            require_login(request)
            with reader() as conn:
                ctx = views.hosts_list(conn, live(conn)) if conn else {"hosts": []}
            return render(request, "hosts.html", {"page": "hosts", "v": ctx})

        @app.get("/partials/hosts", response_class=HTMLResponse)
        async def hosts_partial(request: Request):
            require_login(request)
            with reader() as conn:
                ctx = views.hosts_list(conn, live(conn)) if conn else {"hosts": []}
            return render(request, "partials/hosts.html", {"v": ctx})

        @app.post("/hosts/update")
        async def update_hosts(request: Request, host: str = Form(""), action: str = Form("update")):
            """Ask one host, or every host that's behind, to install the
            hub's commit; or cancel a request that hasn't been picked up."""
            require_login(request)
            # The session cookie is SameSite=strict; refuse cross-site posts
            # outright too, for browsers that say where a request came from.
            if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return PlainTextResponse("cross-site request refused", status_code=403)
            target = hub.hub_revision()
            client = request.client.host if request.client else "?"
            now = time.time()
            if action == "cancel" and hub.HOST_RE.match(host):
                if hub.cancel_update(hub_conn, host):
                    log.info("Update for %s cancelled from %s", host, client)
            elif action == "update" and target:
                if host == "*":
                    ids = hub.request_update_all(hub_conn, target, now)
                elif hub.HOST_RE.match(host) and hub.request_update(hub_conn, host, target, now):
                    ids = [host]
                else:
                    ids = []
                if ids:
                    log.info("Update to %s requested for %s from %s", target, ", ".join(ids), client)
            return RedirectResponse("/", status_code=303)

        def finding_post(request: Request, host: str, next: str) -> str | None:
            """Checks shared by accept and un-accept. Returns the page to go
            back to; raises the response to send when a check fails."""
            require_login(request)
            # Same check as /hosts/update: the session cookie is SameSite=strict,
            # and a browser that says where a request came from can't be cross-site.
            if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                raise HTTPException(403, "cross-site request refused")
            if not hub.HOST_RE.match(host) or \
                    not hub_conn.execute("SELECT 1 FROM hosts WHERE id = ?", (host,)).fetchone():
                raise HTTPException(404)
            return _safe_next(next) if next else f"/h/{host}/"

        @app.post("/h/{host}/findings/accept")
        async def accept_finding(request: Request, host: str, rule: str = Form(""), key: str = Form(""),
                                 note: str = Form(""), next: str = Form("")):
            """Accept an open finding with a note (1 to 500 characters). It
            stays in the database, leaves the counts and comes back when what
            was accepted changes."""
            try:
                back = finding_post(request, host, next)
            except HTTPException as exc:
                if exc.status_code == 403:
                    return PlainTextResponse(exc.detail, status_code=403)
                raise
            note = note.replace("\r\n", "\n").strip()
            if not 1 <= len(note) <= 500 or any(ch not in "\n\t" and unicodedata.category(ch) in ("Cc", "Cf")
                                                for ch in note):
                flash(request, "A note of 1 to 500 characters is required to accept a finding.", error=True)
            elif len(rule) > 60 or len(key) > 300:
                flash(request, "That finding was not found.", error=True)
            else:
                by = str(request.session.get("user") or "admin")
                item = db.accept_finding(hub_conn, host, rule, key, note, by, time.time())
                if item is None:
                    flash(request, "That finding is no longer open.", error=True)
                else:
                    log.info("Finding %s %s on %s accepted by %s from %s", rule, key, host, by,
                             request.client.host if request.client else "?")
                    flash(request, f"Accepted: {item['title']}")
            return RedirectResponse(back, status_code=303)

        @app.post("/h/{host}/findings/unaccept")
        async def unaccept_finding(request: Request, host: str, rule: str = Form(""), key: str = Form(""),
                                   next: str = Form("")):
            try:
                back = finding_post(request, host, next)
            except HTTPException as exc:
                if exc.status_code == 403:
                    return PlainTextResponse(exc.detail, status_code=403)
                raise
            old = db.unaccept_finding(hub_conn, host, rule, key, time.time()) \
                if len(rule) <= 60 and len(key) <= 300 else None
            if old is None:
                flash(request, "That finding was not accepted.", error=True)
            else:
                log.info("Finding %s %s on %s un-accepted from %s", rule, key, host,
                         request.client.host if request.client else "?")
                flash(request, f"Un-accepted: {old['title']}")
            return RedirectResponse(back, status_code=303)

        add_ingest(app, cfg, hub_conn)
    else:
        add_pages("")

    return app


async def _hub_chores(conn, cfg: Config, config_file: Path | None) -> None:
    """Every minute, flag hosts that stopped reporting. Every hour, apply
    [retention] to every host's rows. Backups run on their own schedule.
    Retention and backup settings are read again on each pass, so a change on
    the Settings page applies at the next one."""
    last_prune = 0.0
    while True:
        now = time.time()
        try:
            live = settings.effective(cfg, conn)
            hub.check_silent(conn, now)
            if now - last_prune > 3600:
                r = live.retention
                db.prune(conn, now, live.metrics_hours, r.events_days, r.resolved_findings_days)
                last_prune = now
            if config_file is not None:
                from .. import backup
                path = await asyncio.to_thread(backup.scheduled, live, config_file)
                if path:
                    log.info("backup written to %s", path)
        except Exception:
            log.exception("hub housekeeping failed")
        await asyncio.sleep(60)


def add_ingest(app: FastAPI, cfg: Config, conn) -> None:
    """POST /api/v1/ingest: a collector's upload. Authenticated by the host's
    token, not the login. Every refusal is logged as
    "Refused upload from <address>: <reason>" for fail2ban."""
    bad_tokens = RateLimiter(limit=10, window=300)   # per address
    per_host = RateLimiter(limit=120, window=60)     # uploads per host
    cap = cfg.hub.max_upload_mb * 2**20
    unpacked_cap = cfg.hub.max_unpacked_mb * 2**20

    @app.post("/api/v1/ingest")
    async def ingest(request: Request):
        client = request.client.host if request.client else "unknown"

        def refuse(status: int, reason: str) -> Response:
            log.warning("Refused upload from %s: %s", client, reason)
            return PlainTextResponse(reason, status_code=status)

        if bad_tokens.blocked(client):
            return refuse(429, "too many refused uploads; wait a few minutes")
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        row = hub.host_for_token(conn, token)
        if row is None:
            bad_tokens.fail(client)
            return refuse(401, "unknown token")
        if per_host.blocked(row["id"]):
            return refuse(429, f"{row['id']} is uploading too often")
        per_host.fail(row["id"])
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return refuse(415, "send application/json")
        encoding = request.headers.get("content-encoding", "").strip().lower()
        if encoding not in ("", "gzip"):
            return refuse(415, "send gzip or no encoding")
        try:
            if int(request.headers.get("content-length", "0")) > cap:
                return refuse(413, "upload too large")
        except ValueError:
            return refuse(400, "bad Content-Length")
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > cap:
                return refuse(413, "upload too large")
        try:
            up = hub.unpack(bytes(body), encoding == "gzip", unpacked_cap)
        except hub.UploadRefused as exc:
            return refuse(exc.status, exc.reason)
        if up.host != row["id"]:
            bad_tokens.fail(client)
            return refuse(403, f"this token belongs to {row['id']}, not {up.host}")
        if up.seq <= row["last_seq"]:
            log.info("Stale upload from %s (%s): seq %d, already at %d", client, row["id"], up.seq, row["last_seq"])
            return JSONResponse({"last_seq": row["last_seq"]}, status_code=409)
        target = hub.store(conn, row, up, time.time(), client)
        reply = {"last_seq": up.seq}
        if target:
            reply["update_to"] = target
        return JSONResponse(reply)
