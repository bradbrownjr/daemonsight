"""scripts/check_directive.py: the weekly watcher for a replaced directive. A fake HTTP server stands in for www.cisa.gov."""

import hashlib
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from daemonsight.cve import priority

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_directive", ROOT / "scripts" / "check_directive.py")
cd = importlib.util.module_from_spec(spec)
sys.modules["check_directive"] = cd
spec.loader.exec_module(cd)

# The markup of the real pages (cisa.gov, November 2026): the title, the page heading and, on a revoked directive, the first
# paragraph of the rich-text section. Other directives are listed as teasers at the foot, revoked ones included.
TEASERS = ('<article class="c-teaser"><h3 class="c-teaser__title"><a href="/news-events/directives/bod-22-01-x-revoked">'
           '<span>BOD 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities (Revoked)</span></a></h3></article>')


def page(revoked: bool) -> str:
    title = "BOD 26-04: Prioritizing Security Updates Based on Risk" + (" (Revoked)" if revoked else "")
    banner = ('<p><strong>This Directive has been revoked. It is superseded by </strong>'
              '<a href="/news-events/directives/bod-27-01-next" title="BOD 27-01">BOD 27-01: Next</a>.</p>' if revoked else "")
    return (f'<!DOCTYPE html><html><head><title>{title} | CISA</title></head><body>'
            f'<h1 class="c-page-title__title"><span>{title}</span></h1>'
            f'<div class="l-page-section--rich-text">{banner}<p>This page contains a web-friendly version of the directive.</p></div>'
            f'{TEASERS}</body></html>')


IMAGE = b"\x89PNG fake table image"
IMAGE_SHA = hashlib.sha256(IMAGE).hexdigest()


@pytest.fixture
def cisa():
    """A server with /dir (the page), /old (redirects to /dir-revoked), /table.png and /gone (500). `state` picks what they answer."""
    state = {"page": page(False), "image": IMAGE, "image_type": "image/png", "status": 200}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path in ("/old", "/offsite"):
                self.send_response(301)
                self.send_header("Location", "/dir-revoked" if self.path == "/old" else "https://example.invalid/x")
                self.end_headers()
                return
            code = 500 if self.path == "/gone" else state["status"]
            body, ctype = ((state["page"].encode(), "text/html") if self.path.startswith("/dir")
                           else (state["image"], state["image_type"]))
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["base"] = f"http://127.0.0.1:{srv.server_port}"
    yield state
    srv.shutdown()


def get(url, limit):
    return cd.fetch(url, limit, allow_http=True, hosts=("127.0.0.1",))


def table(cisa, url="/dir", sha=IMAGE_SHA):
    return {"directive": {"name": "CISA BOD 26-04", "url": cisa["base"] + url, "table_url": cisa["base"] + "/table.png",
                          "table_sha256": sha}}


def run(cisa, **kw):
    return cd.check(table(cisa, **kw), get=get)


def test_no_change(cisa):
    r = run(cisa)          # the teaser for a revoked directive further down the page is not a banner
    assert not r.changed and not r.errors and r.new_sha == IMAGE_SHA


def test_a_revoked_banner_is_found(cisa):
    cisa["page"] = page(True)
    r = run(cisa)
    assert r.changed and not r.errors
    assert "has been revoked" in r.changes[0] and "BOD 27-01" in r.changes[0]
    assert ("BOD 27-01: Next", cisa["base"] + "/news-events/directives/bod-27-01-next") in r.links
    body = cd.issue_body(r)
    assert "{{" not in body and "BOD 27-01" in body and cisa["base"] + "/table.png" in body


def test_the_address_redirecting_to_a_revoked_page_is_a_change(cisa):
    r = run(cisa, url="/old")
    assert r.changed and "now redirects" in r.changes[0] and r.changes[0].endswith("/dir-revoked")


def test_the_table_image_changing_is_a_change(cisa):
    cisa["image"] = IMAGE + b" new"
    r = run(cisa)
    assert r.changed and IMAGE_SHA in r.changes[0] and hashlib.sha256(cisa["image"]).hexdigest() in r.changes[0]


def test_a_fetch_failure_is_an_error_and_not_a_change(cisa):
    r = run(cisa, url="/gone")
    assert not r.changed and r.errors and "HTTP 500" in r.errors[0]
    cisa["status"] = 404
    r = run(cisa)
    assert not r.changed and len(r.errors) == 2


def test_an_image_that_is_not_an_image_is_an_error(cisa):
    cisa["image_type"] = "text/html"
    r = run(cisa)
    assert not r.changed and "expected an image" in r.errors[0]


def test_a_missing_stored_hash_is_an_error(cisa):
    r = run(cisa, sha="")
    assert not r.changed and "table_sha256" in r.errors[0]


def test_a_redirect_off_the_site_is_refused(cisa):
    with pytest.raises(cd.FetchError):
        get(cisa["base"] + "/offsite", 1000)
    with pytest.raises(cd.FetchError):
        cd.fetch("http://www.cisa.gov/x", 1000)
    with pytest.raises(cd.FetchError):
        cd.fetch("https://example.com/x", 1000)


def test_the_size_limit(cisa):
    cisa["image"] = b"x" * 5000
    with pytest.raises(cd.FetchError, match="larger than"):
        get(cisa["base"] + "/table.png", 1000)


def make_dir(tmp_path, cisa, sha=IMAGE_SHA):
    (tmp_path / "current.json").write_text('{"table": "t.json"}')
    (tmp_path / "t.json").write_text(json.dumps(table(cisa, sha=sha)))
    return tmp_path


def test_main_end_to_end(cisa, tmp_path, monkeypatch):
    d = make_dir(tmp_path, cisa)
    out, body = tmp_path / "out", tmp_path / "body.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    args = ["--dir", str(d), "--body-file", str(body)]
    assert cd.main(args, get=get) == 0 and "changed=false" in out.read_text() and not body.exists()
    cisa["page"] = page(True)
    assert cd.main(args, get=get) == 0
    assert "changed=true" in out.read_text() and f"title={cd.TITLE}" in out.read_text() and "revoked" in body.read_text()
    body.unlink()
    cisa["status"] = 500        # nothing can be fetched: a failure and no issue text
    assert cd.main(args, get=get) == 1 and not body.exists()


def test_the_shipped_table_names_a_valid_file_with_a_hash():
    path, doc = cd.active_table(cd.DEFAULT_DIR)
    t = priority.parse(doc)
    assert len(t.table_sha256) == 64 and t.url.startswith("https://www.cisa.gov/")
