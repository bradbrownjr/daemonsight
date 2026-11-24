"""The hub's daily fetch of the published prioritisation table (cve/priority_fetch.py), the Settings switch, the event and the
re-rating it triggers, and the data feeds card."""

import asyncio
import copy
import json
import time
from pathlib import Path

import httpx
import pytest

from daemonsight import config, db, settings
from daemonsight.config import Config
from daemonsight.cve import priority, priority_fetch as pf, run

from .test_cve import DAY, page_client, put_inventory, seed_hub, serve
from .test_hub import hub_cfg, token  # noqa: F401 (fixtures)

BUNDLED = json.loads((Path(priority.__file__).parent.parent / "data" / "priority" / "bod-26-04.json").read_text())


def table(version=2, name="CISA BOD 27-01", **severity):
    d = copy.deepcopy(BUNDLED)
    d["version"] = version
    d["directive"]["name"] = name
    d["severity"].update(severity)
    return d


class Repo:
    """A fake raw.githubusercontent.com: files by name, ETags, and a log of the requests."""

    def __init__(self, **files):
        self.files = {"current.json": {"table": "bod-27-01.json"}, "bod-27-01.json": table()}
        self.files.update(files)
        self.calls = []
        self.raw = {}              # name -> bytes to send instead of the JSON of `files`
        self.redirect = {}         # name -> Location

    def set(self, name, doc):
        self.files[name] = doc
        self.raw.pop(name, None)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.url.host, request.url.path.rsplit("/", 1)[-1], dict(request.headers)))
        assert request.headers["user-agent"].startswith("DaemonSight/")
        if request.url.host != pf.HOST:
            return httpx.Response(200, content=b"{}")
        name = request.url.path.rsplit("/", 1)[-1]
        assert request.url.path == "/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/" + name
        if name in self.redirect:
            return httpx.Response(302, headers={"location": self.redirect[name]})
        if name not in self.files:
            return httpx.Response(404)
        body = self.raw.get(name) or json.dumps(self.files[name]).encode()
        etag = '"' + str(hash(body)) + '"'
        if request.headers.get("if-none-match") == etag:
            return httpx.Response(304)
        return httpx.Response(200, content=body, headers={"etag": etag})

    def client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler), follow_redirects=True)

    def asked(self, host=pf.HOST):
        return [c for c in self.calls if c[0] == host]


CLOCK = [1_000_000.0]


def refresh(tmp_path, repo, now=None, enabled=True, client=None):
    """One daily step. Without `now`, the clock moves on two days since the last call that had none."""
    if now is None:
        CLOCK[0] += 2 * DAY
        now = CLOCK[0]
    return asyncio.run(pf.refresh(tmp_path, now, enabled, client or repo.client()))


def override(tmp_path) -> Path:
    return tmp_path / priority.OVERRIDE


def test_the_published_pointer_names_a_table_that_passes_the_check():
    d = Path(priority.__file__).parent.parent / "data" / "priority"
    pointer = json.loads((d / "current.json").read_text())
    assert set(pointer) == {"table"} and pf.NAME_RE.fullmatch(pointer["table"])
    assert priority.parse(json.loads((d / pointer["table"]).read_text())).version == priority.bundled().version


def test_a_newer_table_is_installed_and_used(tmp_path):
    repo = Repo()
    up = refresh(tmp_path, repo)
    assert up == pf.Update("CISA BOD 27-01", 2, "bod-27-01.json")
    assert json.loads(override(tmp_path).read_text())["version"] == 2
    t = priority.load(tmp_path)
    assert (t.version, t.name) == (2, "CISA BOD 27-01") and t.source == str(override(tmp_path))
    assert not list(override(tmp_path).parent.glob("*.part"))
    d = pf.describe(tmp_path)
    assert d["origin"] == "fetched" and d["when"] == CLOCK[0] and not d["error"]


def test_it_asks_once_a_day_and_then_with_the_validators(tmp_path):
    repo = Repo()
    assert refresh(tmp_path, repo, 1000.0) is not None and len(repo.asked()) == 2
    assert refresh(tmp_path, repo, 1000.0 + 3600) is None and len(repo.asked()) == 2     # not due
    assert refresh(tmp_path, repo, 1000.0 + DAY + 1) is None
    again = repo.asked()[2:]
    assert [c[1] for c in again] == ["current.json", "bod-27-01.json"] and all("if-none-match" in c[2] for c in again)
    assert json.loads(override(tmp_path).read_text())["version"] == 2       # a 304 changed nothing
    assert pf.read_state(tmp_path)["status"] == "not modified" or pf.read_state(tmp_path)["status"] == "ok"
    # a new version of the same file is fetched in full, the pointer's 304 notwithstanding
    repo.set("bod-27-01.json", table(3))
    up = refresh(tmp_path, repo, 1000.0 + 2 * DAY + 2)
    assert up and up.version == 3 and priority.load(tmp_path).version == 3


def test_a_304_for_both_files(tmp_path):
    repo = Repo()
    refresh(tmp_path, repo, 0.0)
    codes = []
    orig = repo.handler

    def spy(request):
        r = orig(request)
        codes.append(r.status_code)
        return r
    repo.handler = spy
    assert refresh(tmp_path, repo, DAY + 5.0) is None
    assert codes == [304, 304]


def test_the_same_or_an_older_version_is_ignored(tmp_path):
    repo = Repo(**{"bod-27-01.json": table(1, "CISA BOD 26-04")})          # the bundled version
    assert refresh(tmp_path, repo) is None and not override(tmp_path).exists()
    assert pf.read_state(tmp_path)["status"] == "ok"
    # installed v3; the repository falls back to v2: ignored, v3 stays
    repo.set("bod-27-01.json", table(3))
    assert refresh(tmp_path, repo).version == 3
    repo.set("bod-27-01.json", table(2))
    assert refresh(tmp_path, repo) is None and priority.load(tmp_path).version == 3
    repo.set("bod-27-01.json", table(3, "CISA BOD 27-02"))                    # the same version again, other content
    assert refresh(tmp_path, repo) is None and priority.load(tmp_path).name == "CISA BOD 27-01"


def test_an_invalid_table_is_refused_and_what_is_there_stays(tmp_path):
    repo = Repo()
    refresh(tmp_path, repo, 0.0)
    before = override(tmp_path).read_bytes()
    bad = table(3)
    bad["rows"].pop()
    repo.set("bod-27-01.json", bad)
    assert refresh(tmp_path, repo, DAY + 1.0) is None
    assert override(tmp_path).read_bytes() == before and priority.load(tmp_path).version == 2
    st = pf.read_state(tmp_path)
    assert st["status"] == "error" and "refused" in st["detail"] and "16 rows" in st["detail"]
    assert pf.describe(tmp_path)["error"] == st["detail"]
    for junk in (b"not json", b"[]", b'{"version": 9}', b"\xff\xfe"):
        repo.raw["bod-27-01.json"] = junk
        assert refresh(tmp_path, repo) is None and override(tmp_path).read_bytes() == before
        assert pf.read_state(tmp_path)["status"] == "error"
    # the next good table clears the error
    repo.set("bod-27-01.json", table(4))
    assert refresh(tmp_path, repo).version == 4 and not pf.describe(tmp_path)["error"]


def test_a_bad_pointer_is_refused(tmp_path):
    for pointer in ({"table": "../x.json"}, {"table": "current.json"}, {"table": "x.sh"}, {"table": "a.json", "x": 1}, {"t": 1}, [1]):
        repo = Repo(**{"current.json": pointer})
        assert refresh(tmp_path, repo) is None and not override(tmp_path).exists()
        assert pf.read_state(tmp_path)["status"] == "error"
        assert len(repo.asked()) == 1               # the table was never asked for


def test_the_size_cap(tmp_path):
    repo = Repo()
    big = json.dumps(table(2)).encode() + b" " * (pf.MAX_BYTES + 1)
    repo.raw["bod-27-01.json"] = big
    assert refresh(tmp_path, repo) is None and not override(tmp_path).exists()
    assert "larger than 256 KB" in pf.read_state(tmp_path)["detail"]

    async def chunks():           # no Content-Length: the cap counts the bytes as they arrive
        for _ in range(40):
            yield b" " * 8192
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path.endswith("current.json"):
            return httpx.Response(200, json={"table": "t.json"})
        return httpx.Response(200, content=chunks())
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert refresh(tmp_path, None, client=client) is None
    assert seen[-1].endswith("t.json") and "larger than 256 KB" in pf.read_state(tmp_path)["detail"]
    # a table the loader would refuse for its size (over 64 KB) is refused here too
    repo = Repo()
    repo.raw["bod-27-01.json"] = json.dumps(table(2)).encode() + b" " * (priority.MAX_FILE_BYTES + 1)
    assert refresh(tmp_path, repo) is None and "larger than 64 KB" in pf.read_state(tmp_path)["detail"]


def test_a_redirect_off_the_host_is_not_followed(tmp_path):
    repo = Repo()
    repo.redirect["current.json"] = "https://evil.example/bradbrownjr/daemonsight/current.json"
    assert refresh(tmp_path, repo) is None and not repo.asked("evil.example")
    assert "not a source" in pf.read_state(tmp_path)["detail"]
    repo.redirect["current.json"] = "http://raw.githubusercontent.com/x"       # plain http
    assert refresh(tmp_path, repo) is None and "not a source" in pf.read_state(tmp_path)["detail"]
    repo.files["moved.json"] = {"table": "bod-27-01.json"}                      # an on-host redirect is followed
    repo.redirect["current.json"] = "/bradbrownjr/daemonsight/main/src/daemonsight/data/priority/moved.json"
    assert refresh(tmp_path, repo) is not None


def test_an_unreachable_server_keeps_the_table_and_is_tried_again_in_an_hour(tmp_path):
    repo = Repo()
    refresh(tmp_path, repo, 0.0)

    def down(request):
        raise httpx.ConnectError("no route")
    client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    assert asyncio.run(pf.refresh(tmp_path, DAY + 1.0, True, client)) is None
    assert priority.load(tmp_path).version == 2
    assert pf.describe(tmp_path)["error"] == "ConnectError"
    assert not pf.is_due(pf.read_state(tmp_path), DAY + 1.0 + 1800) and pf.is_due(pf.read_state(tmp_path), DAY + 1.0 + 3601)
    broken = Repo()
    broken.files.pop("current.json")
    assert refresh(tmp_path, broken, 2 * DAY) is None and "HTTP 404" in pf.describe(tmp_path)["error"]


def test_the_switch_off_asks_for_nothing_and_removes_a_fetched_table(tmp_path):
    repo = Repo()
    refresh(tmp_path, repo, 0.0)
    assert priority.load(tmp_path).version == 2
    n = len(repo.calls)
    assert refresh(tmp_path, repo, 5 * DAY, enabled=False) is None
    assert len(repo.calls) == n and not override(tmp_path).exists() and priority.load(tmp_path).version == 1
    d = pf.describe(tmp_path, enabled=False)
    assert d["origin"] == "bundled" and not d["enabled"]
    # a table the administrator placed is theirs: not removed
    override(tmp_path).write_text(json.dumps(table(7, "Mine")))
    assert refresh(tmp_path, repo, 6 * DAY, enabled=False) is None and priority.load(tmp_path).name == "Mine"
    assert len(repo.calls) == n
    # switched on again: asked at once, but the administrator's table still wins
    assert refresh(tmp_path, repo, 6 * DAY + 1) is None and priority.load(tmp_path).name == "Mine"
    assert "you placed" in pf.describe(tmp_path)["note"] and pf.describe(tmp_path)["origin"] == "file"
    override(tmp_path).unlink()
    assert refresh(tmp_path, repo, 8 * DAY).version == 2


def test_a_fetched_table_the_bundled_one_has_caught_up_with_is_dropped(tmp_path, monkeypatch):
    repo = Repo()
    refresh(tmp_path, repo, 0.0)
    import dataclasses
    newer = dataclasses.replace(priority.bundled(), version=2)
    monkeypatch.setattr(priority, "bundled", lambda: newer)
    monkeypatch.setattr(priority, "_bundled_table", newer)
    assert refresh(tmp_path, repo, DAY + 1.0) is None
    assert not override(tmp_path).exists()


# ---- the chore: the event and the re-rating ----------------------------------------------------------------------------

def raw_override(repo):
    return {pf.HOST: repo.handler}


def test_the_chore_logs_the_update_and_rates_the_findings_again(tmp_path, hub_cfg, monkeypatch):  # noqa: F811
    hub_cfg.cve.enabled = True
    state = db.connect_writer(hub_cfg.db_path)
    state.execute("INSERT INTO hosts (id, token_hash, created_at) VALUES ('web1', 'x', 0)")
    put_inventory(state, "web1", [["brotli", "1.0.9-2", ["libbrotli1"]]])
    repo = Repo(**{"bod-27-01.json": table(2, "CISA BOD 27-01", **{"14": "critical"})})
    pub = {"done": False}
    real = repo.handler

    def gated(request):          # the repository publishes the new table only after the first pass
        if request.url.host == pf.HOST and not pub["done"]:
            return httpx.Response(404)
        return real(request)
    repo.handler = gated
    now = time.time()

    async def go():
        ch = run.Chore(hub_cfg, state, serve(tmp_path, override={pf.HOST: gated}))
        await ch.run_once(now)
        sev = lambda: {(r["rule"], r["key"]): r["severity"] for r in db.open_findings(state, "web1")}[("cve.package", "brotli")]
        assert sev() == "high"                                              # 14 days is High in BOD 26-04
        assert not [e for e in db.recent_events(state, db.HUB_HOST, 20) if e["title"].startswith("Prioritisation")]
        pub["done"] = True
        await ch.run_once(now + DAY + 10)
        assert not ch.dirty                                                  # the pass worked the findings out again
        assert sev() == "critical"                                           # rated by the new table
        titles = [e["title"] for e in db.recent_events(state, db.HUB_HOST, 20)]
        assert titles.count("Prioritisation table updated to CISA BOD 27-01 v2") == 1
        await ch.run_once(now + 2 * DAY + 20)                                # nothing new: no second event
        assert [e["title"] for e in db.recent_events(state, db.HUB_HOST, 20)].count("Prioritisation table updated to CISA BOD 27-01 v2") == 1
        # the switch on the Settings page applies on the next pass, without a restart
        settings.save(state, hub_cfg, {"cve.priority_updates": False}, "admin")
        await ch.run_once(now + 3 * DAY)
        assert sev() == "high" and not override_file(hub_cfg).exists()
    asyncio.run(go())
    state.close()


def override_file(cfg) -> Path:
    return Path(cfg.data_dir) / priority.OVERRIDE


def test_the_chore_marks_findings_dirty_when_a_table_is_installed(tmp_path):
    cfg = Config(host_id="hub", data_dir=str(tmp_path / "d"))
    cfg.hub.enabled = True
    state = db.connect_writer(cfg.db_path)
    ch = run.Chore(cfg, state, Repo().client())
    ch.dirty = False
    asyncio.run(ch._fetch_priority(1000.0))
    assert ch.dirty
    assert [e["title"] for e in db.recent_events(state, db.HUB_HOST, 5)] == ["Prioritisation table updated to CISA BOD 27-01 v2"]
    state.close()


# ---- the setting and the page --------------------------------------------------------------------------------------------

def test_the_setting_defaults_on_and_can_be_turned_off(hub_cfg, tmp_path):  # noqa: F811
    f = settings.BY_KEY["cve.priority_updates"]
    assert f.kind == "bool" and f.label == "Fetch prioritisation table updates from the DaemonSight repository"
    assert config.Config().cve.priority_updates is True
    state = db.connect_writer(hub_cfg.db_path)
    settings.save(state, hub_cfg, {"cve.priority_updates": False}, "admin")
    assert settings.effective(hub_cfg, state).cve.priority_updates is False and hub_cfg.cve.priority_updates is True
    state.close()


def test_the_data_feeds_card_shows_the_table_and_a_fetch_error(hub_cfg, token, tmp_path):  # noqa: F811
    c = seed_hub(hub_cfg, token, tmp_path)
    html = c.get("/h/testhost/vulnerabilities").text
    assert "Prioritisation table" in html and "CISA BOD 26-04, Table 1" in html and "version 1" in html
    assert "Bundled with this version" in html and "Not checked yet" in html
    data = Path(hub_cfg.data_dir)
    refresh(data, Repo())
    html = c.get("/h/testhost/vulnerabilities").text
    assert "CISA BOD 27-01, Table 1" in html and "version 2" in html and "Fetched from the DaemonSight repository" in html
    assert "Could not update the table" not in html
    st = pf.read_state(data)
    st.update(status="error", detail="HTTP 503")
    pf.write_state(data, st)
    assert "Could not update the table: HTTP 503" in c.get("/h/testhost/vulnerabilities").text
    hub_cfg.cve.priority_updates = False
    assert "Fetching updates is off" in c.get("/h/testhost/vulnerabilities").text
