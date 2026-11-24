#!/usr/bin/env python3
"""Has CISA changed the directive the prioritisation table comes from?

Run weekly by .github/workflows/directive-watch.yml. It reads the active table file (src/daemonsight/data/priority/current.json
names it), then looks for two signs that the table needs a person's attention:

* the directive's page says it has been revoked or superseded. When CISA revoked BOD 22-01 the page gained "This Directive has
  been revoked. It is superseded by BOD 26-04." (in a paragraph at the top of the page, with the title "(Revoked)" and the
  address ending "-revoked"; archived page dated June 10, 2026);
* the table image at `directive.table_url` no longer has the SHA-256 stored as `directive.table_sha256`.

The table is published only as an image, so a new table needs a person to read it. This script detects, it does not interpret.

Exit status: 0 = checked (changed or not; see the outputs), 1 = a page could not be fetched (a failure, not a change). When it
finds a change it writes the issue text to --body-file and `changed=true` to $GITHUB_OUTPUT. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

PAGE_LIMIT = 5 << 20
IMAGE_LIMIT = 10 << 20
HOSTS = ("www.cisa.gov",)
TITLE = "CISA directive change: review the prioritisation table"
USER_AGENT = "DaemonSight-directive-watch (+https://github.com/bradbrownjr/daemonsight)"
DEFAULT_DIR = Path(__file__).resolve().parent.parent / "src" / "daemonsight" / "data" / "priority"


class FetchError(Exception):
    pass


@dataclass
class Fetched:
    url: str            # the address finally answered (after redirects)
    content_type: str
    body: bytes


def fetch(url: str, limit: int, allow_http: bool = False, hosts: tuple = HOSTS) -> Fetched:
    """GET `url` (https on an allowed host; redirects must stay on one) and return at most `limit` bytes, or raise FetchError."""
    def check(u: str) -> None:
        p = urllib.parse.urlsplit(u)
        if not (p.scheme == "https" or (allow_http and p.scheme == "http")) or p.hostname not in hosts:
            raise FetchError(f"{u} is not an https address on {', '.join(hosts)}")

    class Guard(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            check(urllib.parse.urljoin(req.full_url, newurl))
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    check(url)
    opener = urllib.request.build_opener(Guard)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=60) as r:
            check(r.geturl())
            body = r.read(limit + 1)
            if len(body) > limit:
                raise FetchError(f"{url} is larger than {limit >> 10} KB")
            return Fetched(r.geturl(), r.headers.get("Content-Type", ""), body)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"{url}: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchError(f"{url}: {type(exc).__name__}: {exc}"[:300]) from None


# --- the page ------------------------------------------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.I | re.S)
_MARK_RE = re.compile(r"\((?:revoked|superseded|rescinded)\)", re.I)
_SAYS_RE = re.compile(r"this directive (?:has been|is) (?:revoked|superseded|rescinded)|\bis superseded by\b", re.I)
_BY_RE = re.compile(r"superseded by\s*(?:</[a-z]+>\s*)*<a\s[^>]*?href=\"([^\"]+)\"[^>]*>(.*?)</a>", re.I | re.S)


def _text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def find_banner(page: str) -> dict | None:
    """What the page says when its directive has been revoked or superseded, else None. Only the directive's own text counts: the
    title, the heading and the paragraphs before the page's first "teaser" (the list of other directives at the foot, which names
    revoked ones). Returns {"text": the sentence, "successor": its name or "", "successor_url": its address or ""}."""
    page = re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.I | re.S)
    head = page.split("c-teaser", 1)[0]
    parts = []
    for rx in (_TITLE_RE, _H1_RE):
        m = rx.search(head)
        if m:
            parts.append(_text(m.group(1)))
    body = _text(head)
    says = _SAYS_RE.search(body)
    marked = any(_MARK_RE.search(p) for p in parts)
    if not says and not marked:
        return None
    if says:
        text = body[says.start():says.start() + 160].strip()
        if "." in text[says.end() - says.start():]:
            text = text[:text.index(".", says.end() - says.start()) + 1]
    else:
        text = parts[0]
    by = _BY_RE.search(head)
    return {"text": text[:300], "successor": _text(by.group(2))[:200] if by else "",
            "successor_url": html.unescape(by.group(1)) if by else ""}


# --- the check -----------------------------------------------------------------------------------------------------------

@dataclass
class Result:
    changes: list = field(default_factory=list)      # what changed, one line each
    errors: list = field(default_factory=list)       # what could not be fetched
    links: list = field(default_factory=list)        # (label, address)
    directive: str = ""
    old_sha: str = ""
    new_sha: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.changes)


def active_table(directory: Path) -> tuple[Path, dict]:
    """(path, decoded JSON) of the table file that current.json names."""
    pointer = json.loads((directory / "current.json").read_text(encoding="utf-8"))
    name = pointer["table"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", name) or name == "current.json":
        raise ValueError(f"current.json names {name!r}, which is not a table file")
    path = directory / name
    return path, json.loads(path.read_text(encoding="utf-8"))


def check(table: dict, get=fetch) -> Result:
    """Look at the directive's page and table image. `get(url, limit)` fetches (tests pass their own)."""
    d = table["directive"]
    res = Result(directive=d["name"], old_sha=d.get("table_sha256", ""))
    res.links = [(f"{d['name']}, the directive's page", d["url"]), (f"{d['name']}, the table image", d["table_url"])]
    try:
        page = get(d["url"], PAGE_LIMIT)
    except FetchError as exc:
        res.errors.append(f"the directive's page: {exc}")
    else:
        banner = find_banner(page.body.decode("utf-8", "replace"))
        if banner:
            by = f" It is superseded by {banner['successor']}." if banner["successor"] and "superseded by" not in banner["text"] else ""
            line = f"The page says: \"{banner['text']}{by}\""
            res.changes.append(line)
            if banner["successor_url"]:
                url = urllib.parse.urljoin(page.url, banner["successor_url"])
                res.links.append((banner["successor"] or "the directive that replaces it", url))
        if page.url.rstrip("/").endswith("-revoked") and not d["url"].rstrip("/").endswith("-revoked"):
            res.changes.append(f"The page's address now redirects to {page.url}")
    try:
        image = get(d["table_url"], IMAGE_LIMIT)
        if not image.content_type.lower().startswith("image/"):
            raise FetchError(f"{d['table_url']}: expected an image, got {image.content_type or 'no content type'}")
    except FetchError as exc:
        res.errors.append(f"the table image: {exc}")
    else:
        res.new_sha = hashlib.sha256(image.body).hexdigest()
        if not res.old_sha:
            res.errors.append("the table file has no directive.table_sha256 to compare with")
        elif res.new_sha != res.old_sha:
            res.changes.append(f"The table image changed: SHA-256 was {res.old_sha}, is now {res.new_sha}")
    return res


def issue_body(res: Result) -> str:
    lines = [f"The weekly check of {res.directive} found a change. Read what CISA published, then follow \"When the directive "
             "changes\" in docs/DESIGN.md (Prioritisation).", "", "What changed:", ""]
    lines += [f"- {c}" for c in res.changes]
    if res.errors:
        lines += ["", "Also not fetched in this run:", ""] + [f"- {e}" for e in res.errors]
    lines += ["", "Links:", ""] + [f"- [{label}]({url})" for label, url in res.links]
    lines += ["", "Steps: transcribe the new table into a file in src/daemonsight/data/priority/, bump its version, point "
              "current.json at it, and update directive.table_sha256. Hubs fetch it from there within a day, with no release.",
              "", "Opened by .github/workflows/directive-watch.yml."]
    return "\n".join(lines) + "\n"


def main(argv=None, get=fetch) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="folder with current.json and the table files")
    ap.add_argument("--body-file", type=Path, default=Path("directive-change.md"), help="where to write the issue text")
    args = ap.parse_args(argv)
    path, table = active_table(args.dir)
    res = check(table, get)
    print(f"Table file: {path.name} ({res.directive})")
    for c in res.changes:
        print(f"CHANGED: {c}")
    for e in res.errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if not res.changes and not res.errors:
        print("No change.")
    if res.changed:
        args.body_file.write_text(issue_body(res), encoding="utf-8")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"changed={'true' if res.changed else 'false'}\n")
            fh.write(f"title={TITLE}\n")
    return 1 if res.errors else 0


if __name__ == "__main__":
    sys.exit(main())
