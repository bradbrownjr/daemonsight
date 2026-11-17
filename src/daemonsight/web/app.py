"""The web UI. Read-only: it never touches sockets, logs or tools, only the
collector's database."""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, db
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


def create_app(cfg: Config, *, secret: str | None = None) -> FastAPI:
    if secret is None:
        secret = Path(cfg.web.secret_file).read_text().strip()
    if len(secret) < 32:
        raise RuntimeError(f"session secret in {cfg.web.secret_file} is too short")

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
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
    templates.env.globals["version"] = __version__

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

    def require_login(request: Request) -> None:
        if request.session.get("user") != "admin":
            raise LoginRequired()

    def theme(request: Request) -> str:
        return "light" if request.cookies.get("theme") == "light" else "dark"

    def render(request: Request, name: str, ctx: dict, status: int = 200) -> HTMLResponse:
        ctx = {"theme": theme(request), "path": request.url.path, **ctx}
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

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        require_login(request)
        with reader() as conn:
            ctx = views.overview(conn, cfg) if conn else None
        return render(request, "overview.html", {"page": "overview", "v": ctx})

    @app.get("/partials/overview", response_class=HTMLResponse)
    async def overview_partial(request: Request):
        require_login(request)
        with reader() as conn:
            ctx = views.overview(conn, cfg) if conn else None
        return render(request, "partials/overview.html", {"v": ctx})

    @app.get("/services", response_class=HTMLResponse)
    async def services(request: Request, units: str = "active"):
        require_login(request)
        units = units if units in views.UNIT_FILTERS else "active"
        with reader() as conn:
            ctx = views.services(conn, cfg, units) if conn else None
        return render(request, "services.html", {"page": "services", "v": ctx})

    @app.get("/partials/services", response_class=HTMLResponse)
    async def services_partial(request: Request, units: str = "active"):
        require_login(request)
        units = units if units in views.UNIT_FILTERS else "active"
        with reader() as conn:
            ctx = views.services(conn, cfg, units) if conn else None
        return render(request, "partials/services.html", {"v": ctx})

    @app.get("/partials/logs/{name}", response_class=HTMLResponse)
    async def logs_partial(request: Request, name: str):
        require_login(request)
        with reader() as conn:
            ctx = views.container_logs(conn, cfg, name) if conn else None
        return render(request, "partials/logs.html", {"logs": ctx, "name": name})

    return app
