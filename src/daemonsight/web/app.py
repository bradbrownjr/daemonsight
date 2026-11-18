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
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import db, full_version, hub
from ..config import Config
from . import views
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
               cve_client=None) -> FastAPI:
    if secret is None:
        secret = Path(cfg.web.secret_file).read_text().strip()
    if len(secret) < 32:
        raise RuntimeError(f"session secret in {cfg.web.secret_file} is too short")

    hub_conn = db.connect_writer(cfg.db_path) if cfg.hub.enabled else None

    @asynccontextmanager
    async def lifespan(_app):
        tasks = []
        if hub_conn is not None:
            tasks.append(asyncio.create_task(_hub_chores(hub_conn, cfg, config_file)))
            if cfg.cve.enabled:
                from ..cve import run as cve_run
                tasks.append(asyncio.create_task(cve_run.loop(cfg, hub_conn, cve_client)))
            else:
                from ..cve import run as cve_run
                cve_run.clear_findings(hub_conn, time.time())
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

    def theme(request: Request) -> str:
        return "light" if request.cookies.get("theme") == "light" else "dark"

    def render(request: Request, name: str, ctx: dict, status: int = 200) -> HTMLResponse:
        ctx = {"theme": theme(request), "path": request.url.path, "base": "", "hub": cfg.hub.enabled, **ctx}
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
    async def set_theme(request: Request, next: str = Form("/")):
        require_login(request)
        response = RedirectResponse(_safe_next(next), status_code=303)
        new = "dark" if theme(request) == "light" else "light"
        response.set_cookie("theme", new, max_age=365 * 86400, samesite="strict",
                            secure=cfg.web.secure_cookies, httponly=True)
        return response

    # --- pages ---------------------------------------------------------------
    # On a single host the pages live at /, /exposure ... for this host. On a
    # hub, / lists the hosts and each host's pages live under /h/<host>/.
    pages = {"overview": views.overview, "exposure": views.exposure, "routes": views.routes,
             "services": views.services, "fail2ban": views.jails, "packages": views.packages,
             "vulnerabilities": views.vulnerabilities}

    def resolve(conn, host: str | None) -> tuple[Config, str]:
        if not cfg.hub.enabled:
            return cfg, ""
        if host is None or not hub.HOST_RE.match(host) or \
                not conn.execute("SELECT 1 FROM hosts WHERE id = ?", (host,)).fetchone():
            raise HTTPException(404)
        return views.host_config(conn, cfg, host), f"/h/{host}"

    async def show(request: Request, name: str, host: str | None, partial: bool, units: str = "active"):
        require_login(request)
        with reader() as conn:
            if conn is None:
                if cfg.hub.enabled:
                    raise HTTPException(404)
                ctx, base = None, ""
            else:
                hcfg, base = resolve(conn, host)
                if name == "services":
                    ctx = views.services(conn, hcfg, units if units in views.UNIT_FILTERS else "active")
                else:
                    ctx = pages[name](conn, hcfg)
        template = f"partials/{name}.html" if partial else f"{name}.html"
        return render(request, template, {"page": name, "v": ctx, "base": base})

    async def logs(request: Request, cname: str, host: str | None = None):
        require_login(request)
        with reader() as conn:
            if conn is None:
                ctx, base = None, ""
            else:
                hcfg, base = resolve(conn, host)
                ctx = views.container_logs(conn, hcfg, cname)
        return render(request, "partials/logs.html", {"logs": ctx, "name": cname, "base": base})

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

    if cfg.hub.enabled:
        add_pages("/h/{host}")

        @app.get("/", response_class=HTMLResponse)
        async def hosts_page(request: Request):
            require_login(request)
            with reader() as conn:
                ctx = views.hosts_list(conn, cfg) if conn else {"hosts": []}
            return render(request, "hosts.html", {"page": "hosts", "v": ctx})

        @app.get("/partials/hosts", response_class=HTMLResponse)
        async def hosts_partial(request: Request):
            require_login(request)
            with reader() as conn:
                ctx = views.hosts_list(conn, cfg) if conn else {"hosts": []}
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

        add_ingest(app, cfg, hub_conn)
    else:
        add_pages("")

    return app


async def _hub_chores(conn, cfg: Config, config_file: Path | None) -> None:
    """Every minute, flag hosts that stopped reporting. Every hour, apply
    [retention] to every host's rows. Backups run on their own schedule."""
    last_prune = 0.0
    while True:
        now = time.time()
        try:
            hub.check_silent(conn, now)
            if now - last_prune > 3600:
                r = cfg.retention
                db.prune(conn, now, cfg.metrics_hours, r.events_days, r.resolved_findings_days)
                last_prune = now
            if config_file is not None:
                from .. import backup
                path = await asyncio.to_thread(backup.scheduled, cfg, config_file)
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
