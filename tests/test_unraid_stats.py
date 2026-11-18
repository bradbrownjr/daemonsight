"""Container CPU and memory from Unraid's one statistics subscription: the guard that lets that subscription and no
other through, the graphql-transport-ws exchange (against a fake socket and against a real TLS WebSocket server),
the caps and the timeout, TLS pinning, the key staying out of logs, the poller (including stale data after a failed
sample) and what the Containers and Overview pages show."""

import asyncio
import json
import logging
import re
import ssl
import time
from http import HTTPStatus

import pytest
import websockets
from websockets.asyncio.server import serve

from daemonsight import db
from daemonsight.remote import client, poll, store, unraid
from daemonsight.remote.client import STATS_SUBSCRIPTION, Graph, Net, RemoteError, Sample, fingerprint

from .fake_unraid import KEY, FakeUnraid, load, make_cert, stat
from .test_provenance import check_panels
from .test_remote import NOW, add, cfg, conn, poll_at, run  # noqa: F401 (fixtures)
from .test_remote_web import app_client, c, conn_of, poll_now, polled, save  # noqa: F401 (fixtures)
from .test_hub import hub_cfg  # noqa: F401 (fixture)

CIDS = [c_["id"].split(":", 1)[1] for c_ in load("docker")["data"]["docker"]["containers"]]


@pytest.fixture
def fake():
    return FakeUnraid()


def graph_for(fake: FakeUnraid) -> Graph:
    net = fake.net()
    return Graph("https://tower.test:4443", KEY, net.http(), ws=lambda url: net.websocket(url))


# --- the guard -----------------------------------------------------------------------------------------------

OTHER_DOCUMENTS = [
    "subscription { logFile(path: \"/var/log/syslog\") { content } }",
    "subscription { arraySubscription { state } }",
    "subscription { dockerContainerStats { id cpuPercent memUsage memPercent netIO } }",   # one more field
    STATS_SUBSCRIPTION + " ",
    " " + STATS_SUBSCRIPTION,
    STATS_SUBSCRIPTION + " mutation { x }",
    "subscription { dockerContainerStats { id cpuPercent memUsage memPercent } } subscription { upsUpdates { id } }",
    "mutation { docker { start(id: \"x\") { id } } }",
    "{ docker { containers { id } } }",
    "",
]


@pytest.mark.parametrize("doc", OTHER_DOCUMENTS)
def test_no_other_subscription_can_be_sent(fake, doc):
    g = graph_for(fake)
    with pytest.raises(ValueError):
        run(g.sample(doc))
    assert fake.sockets == []          # nothing was even connected


def test_query_still_refuses_every_subscription_including_the_allowed_one(fake):
    g = graph_for(fake)
    for doc in (STATS_SUBSCRIPTION, "subscription { upsUpdates { id } }", "mutation { x }"):
        with pytest.raises(ValueError):
            run(g.query(doc))
    assert fake.requests == []


def test_a_graph_without_a_websocket_cannot_sample(fake):
    g = Graph("https://tower.test:4443", KEY, fake.net().http())
    with pytest.raises(RemoteError) as e:
        run(g.sample())
    assert e.value.kind == "config"


def test_the_allowed_subscription_is_the_documented_one():
    assert STATS_SUBSCRIPTION == "subscription { dockerContainerStats { id cpuPercent memUsage memPercent } }"
    assert unraid.Q_STATS == STATS_SUBSCRIPTION and unraid.QUERY_OF[unraid.STATS] == STATS_SUBSCRIPTION


# --- the exchange ----------------------------------------------------------------------------------------------

def test_handshake_collection_and_a_clean_finish(fake):
    expected = set(CIDS)
    s = run(graph_for(fake).sample(expected=expected))
    sock = fake.sockets[0]
    # connection_init (the key in its payload), then the one subscription, then complete.
    assert [m["type"] for m in sock.sent] == ["connection_init", "subscribe", "complete"]
    assert sock.sent[0]["payload"] == {"x-api-key": KEY}
    assert sock.sent[1]["payload"] == {"query": STATS_SUBSCRIPTION} and sock.sent[1]["id"] == sock.sent[2]["id"]
    assert sock.url == "wss://tower.test:4443/graphql" and sock.closed and sock.completed
    assert s.covered and set(s.items) == expected and s.messages == len(expected)
    first = s.items[CIDS[0]]
    assert first == {"cpu": 1.5, "mem_usage": "100MiB / 2GiB", "mem_percent": 4.88}
    assert s.seconds < 2     # stopped as soon as every container had reported


def test_terminal_control_sequences_on_an_id_are_stripped(fake):
    """Unraid builds ids from `docker stats` lines; the first line of each refresh carries cursor codes
    (seen live: ESC [ H and ESC [ J ESC [ H before the id)."""
    fake.stats = [stat(f"server:\x1b[J\x1b[H{CIDS[0]}", 3.0, "10MiB / 1GiB", 1.0),
                  stat(f"server:\x1b[H{CIDS[1]}", 4.0, "20MiB / 1GiB", 2.0),
                  stat("server:not-a-docker-id", 9.0, "1MiB / 1GiB", 0.1), stat(CIDS[2], 5.0, "30MiB / 1GiB", 3.0)]
    s = run(graph_for(fake).sample(seconds=0.2))
    assert set(s.items) == set(CIDS[:3]) and s.items[CIDS[0]]["cpu"] == 3.0


def test_the_last_report_of_a_container_wins(fake):
    fake.stats = [stat(CIDS[0], 1.0, "10MiB / 1GiB", 1.0)]
    fake.stats_ticks = 3
    fake.stats[0:1] = [stat(CIDS[0], 1.0, "10MiB / 1GiB", 1.0)]
    s = run(graph_for(fake).sample(seconds=0.2))
    assert s.messages == 3 and len(s.items) == 1


def test_it_stops_at_the_time_limit_and_still_completes(fake):
    fake.stats = fake.stats[:3]                       # never every expected container
    t = time.monotonic()
    s = run(graph_for(fake).sample(expected=set(CIDS), seconds=0.4))
    assert 0.35 < time.monotonic() - t < 3 and not s.covered and len(s.items) == 3
    sock = fake.sockets[0]
    assert sock.completed and sock.closed


def test_the_message_count_is_capped(fake, monkeypatch):
    monkeypatch.setattr(client, "WS_MAX_MESSAGES", 7)
    fake.stats_ticks = 50
    s = run(graph_for(fake).sample(seconds=2))
    assert s.messages == 7 and fake.sockets[0].completed


def test_a_message_over_the_size_cap_is_refused(fake):
    fake.stats = [stat(CIDS[0], 1.0, "x" * (client.WS_MAX_MESSAGE + 1), 1.0)]
    with pytest.raises(RemoteError) as e:
        run(graph_for(fake).sample(seconds=1))
    assert "too large" in e.value.message and fake.sockets[0].closed


def test_a_server_ping_is_answered(fake):
    fake.ws_before_ack = [json.dumps({"type": "ping"})]
    run(graph_for(fake).sample(seconds=0.2))
    assert [m["type"] for m in fake.sockets[0].sent][:2] == ["connection_init", "pong"]


def test_no_ack_in_time_is_an_error_and_the_subscription_is_never_sent(fake, monkeypatch):
    monkeypatch.setattr(client, "ACK_SECONDS", 0.2)
    fake.ws_silent = True
    with pytest.raises(RemoteError) as e:
        run(graph_for(fake).sample(seconds=1))
    assert e.value.kind == "unreachable" and [m["type"] for m in fake.sockets[0].sent] == ["connection_init"]


def test_a_wrong_key_is_an_auth_error(fake):
    g = Graph("https://tower.test:4443", "wrong-key-" + "0" * 20, fake.net().http(),
              ws=lambda url: fake.net().websocket(url))
    with pytest.raises(RemoteError) as e:
        run(g.sample(seconds=1))
    assert e.value.kind == "auth" and "wrong-key" not in e.value.message


def test_an_error_message_from_the_server_is_an_error(fake):
    fake.ws_script = lambda op: [json.dumps({"id": op, "type": "error", "payload": [{"message": "User not found"}]})]
    with pytest.raises(RemoteError) as e:
        run(graph_for(fake).sample(seconds=1))
    assert e.value.kind == "auth"


def test_the_key_is_never_in_an_error_or_a_log(fake, caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    fake.ws_fail = OSError(f"connect failed for {KEY}")
    with pytest.raises(RemoteError) as e:
        run(graph_for(fake).sample(seconds=1))
    assert KEY not in e.value.message and KEY not in caplog.text and e.value.kind == "unreachable"


# --- a real TLS WebSocket server ------------------------------------------------------------------------------

class Server:
    """A graphql-transport-ws server on localhost with a self-signed certificate; records what it receives."""

    def __init__(self, crt, key, messages=None, redirect_to=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.received: list[dict] = []
        self.request_headers: list = []
        self.request_paths: list[str] = []
        self.subprotocol = None
        self.close_code = None
        self.connections = 0
        self.messages = messages if messages is not None else [json.dumps(
            {"id": "1", "type": "next", "payload": {"data": {"dockerContainerStats": stat(CIDS[0], 2.5, "64MiB / 1GiB", 6.25)}}})]
        self.redirect_to = redirect_to

    async def handler(self, ws):
        self.connections += 1
        self.subprotocol = ws.subprotocol
        try:
            async for raw in ws:
                msg = json.loads(raw)
                self.received.append(msg)
                if msg["type"] == "connection_init":
                    await ws.send(json.dumps({"type": "connection_ack"}))
                elif msg["type"] == "subscribe":
                    for m in self.messages:
                        await ws.send(m)
                elif msg["type"] == "complete":
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.close_code = ws.close_code

    def process_request(self, connection, request):
        self.request_headers.append(dict(request.headers))
        self.request_paths.append(request.path)
        if self.redirect_to:
            response = connection.respond(HTTPStatus.FOUND, "")
            response.headers["Location"] = self.redirect_to
            return response
        return None

    def start(self):
        return serve(self.handler, "127.0.0.1", 0, ssl=self.ctx, subprotocols=["graphql-transport-ws"],
                     process_request=self.process_request, max_size=1 << 20)


def real_graph(port: int, tls: str, pem: str | None, key: str = KEY) -> Graph:
    net = Net()
    return Graph(f"https://127.0.0.1:{port}", key, net.http(tls, pem), ws=lambda url: net.websocket(url, tls, pem))


@pytest.fixture
def certs(tmp_path):
    return make_cert(tmp_path / "server", "tower.test")


async def test_a_real_handshake_with_the_pinned_certificate(certs):
    pem, crt, key = certs
    srv = Server(crt, key)
    async with srv.start() as s:
        port = s.sockets[0].getsockname()[1]
        g = real_graph(port, "pin", pem)
        sample = await g.sample(expected={CIDS[0]}, seconds=3)
        await g.aclose()
    assert sample.items == {CIDS[0]: {"cpu": 2.5, "mem_usage": "64MiB / 1GiB", "mem_percent": 6.25}} and sample.covered
    assert srv.subprotocol == "graphql-transport-ws" and srv.request_paths == ["/graphql"]
    assert [m["type"] for m in srv.received] == ["connection_init", "subscribe", "complete"]
    assert srv.received[0]["payload"] == {"x-api-key": KEY}
    assert srv.received[1]["payload"] == {"query": STATS_SUBSCRIPTION}
    # The key is in the first message only: not in the upgrade request (headers, path), and the close is clean.
    assert KEY not in json.dumps(srv.request_headers) and KEY not in "".join(srv.request_paths)
    assert srv.close_code == 1000


async def test_a_different_certificate_is_refused_before_the_key_is_sent(certs, tmp_path):
    pem, crt, key = certs
    other, _, _ = make_cert(tmp_path / "other", "tower.test")
    assert fingerprint(other) != fingerprint(pem)
    srv = Server(crt, key)
    async with srv.start() as s:
        g = real_graph(s.sockets[0].getsockname()[1], "pin", other)
        with pytest.raises(RemoteError) as e:
            await g.sample(seconds=1)
        await g.aclose()
    assert e.value.kind == "tls" and "certificate" in e.value.message and KEY not in e.value.message
    assert srv.received == [] and srv.request_paths == []      # the server saw no upgrade request and no key


async def test_the_normal_check_refuses_a_self_signed_certificate(certs):
    _, crt, key = certs
    srv = Server(crt, key)
    async with srv.start() as s:
        g = real_graph(s.sockets[0].getsockname()[1], "verify", None)
        with pytest.raises(RemoteError) as e:
            await g.sample(seconds=1)
        await g.aclose()
    assert e.value.kind == "tls" and srv.received == []


async def test_a_redirect_is_not_followed(certs):
    pem, crt, key = certs
    target = Server(crt, key)
    async with target.start() as t:
        tport = t.sockets[0].getsockname()[1]
        srv = Server(crt, key, redirect_to=f"wss://127.0.0.1:{tport}/graphql")
        async with srv.start() as s:
            g = real_graph(s.sockets[0].getsockname()[1], "pin", pem)
            with pytest.raises(RemoteError) as e:
                await g.sample(seconds=1)
            await g.aclose()
    assert e.value.kind == "http" and "redirect" in e.value.message.lower()
    assert target.connections == 0 and srv.received == [] and KEY not in e.value.message


async def test_a_real_message_over_the_size_cap_is_refused(certs):
    pem, crt, key = certs
    big = json.dumps({"id": "1", "type": "next", "payload": {"data": {"dockerContainerStats": stat(
        CIDS[0], 1.0, "x" * (client.WS_MAX_MESSAGE * 2), 1.0)}}})
    srv = Server(crt, key, messages=[big])
    async with srv.start() as s:
        g = real_graph(s.sockets[0].getsockname()[1], "pin", pem)
        with pytest.raises(RemoteError):
            await g.sample(seconds=2)
        await g.aclose()


async def test_the_real_exchange_leaves_the_key_out_of_the_websockets_log(certs, caplog):
    pem, crt, key = certs
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("websockets").setLevel(logging.DEBUG)
    srv = Server(crt, key)
    async with srv.start() as s:
        g = real_graph(s.sockets[0].getsockname()[1], "pin", pem)
        await g.sample(expected={CIDS[0]}, seconds=3)
        await g.aclose()
    assert KEY not in caplog.text


async def test_the_real_timeout_ends_the_sample_and_closes(certs):
    pem, crt, key = certs
    srv = Server(crt, key)           # sends one container; two are expected, so the sample runs to its limit
    async with srv.start() as s:
        g = real_graph(s.sockets[0].getsockname()[1], "pin", pem)
        t = time.monotonic()
        sample = await g.sample(expected={CIDS[0], CIDS[1]}, seconds=0.5)
        await g.aclose()
        elapsed = time.monotonic() - t
    assert 0.45 < elapsed < 3 and not sample.covered and len(sample.items) == 1
    assert [m["type"] for m in srv.received][-1] == "complete"


def test_the_proxy_settings_of_the_environment_are_not_used(monkeypatch):
    """The key must go to the address that was typed, not to a proxy from HTTPS_PROXY."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.test:3128")
    cm = Net().websocket("wss://tower.test:4443/graphql")
    assert cm.proxy is None and cm.process_redirect(ValueError("x")).args == ("x",)


# --- parsing ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("970MiB / 94.28GiB", (970 * 2 ** 20, round(94.28 * 2 ** 30))),
    ("2.512GiB / 94.28GiB", (round(2.512 * 2 ** 30), round(94.28 * 2 ** 30))),
    ("0B / 128MiB", (0, 128 * 2 ** 20)),
    ("1.5KiB / 2TiB", (1536, 2 * 2 ** 40)),
    ("-- / --", (None, None)), ("", (None, None)), (None, (None, None)), ("12MiB", (None, None)),
    ("12XB / 1GiB", (None, 2 ** 30)), ("abc / def", (None, None)), ("1MiB / 2GiB / 3", (None, None)),
])
def test_memory_usage_strings(raw, expected):
    assert unraid.parse_mem_usage(raw) == expected


def test_container_ids():
    h = "ab" * 32
    assert unraid.container_id(f"server:{h}") == h and unraid.container_id(h) == h
    assert unraid.container_id(f"server:\x1b[H{h}") == h
    assert unraid.container_id("server:short") is None and unraid.container_id(None) is None


def test_parse_stats_maps_ids_to_names_and_drops_the_rest():
    now = 123.0
    sample = Sample({CIDS[0]: {"cpu": 12.345, "mem_usage": "100MiB / 1GiB", "mem_percent": 9.77},
                     "f" * 64: {"cpu": 1, "mem_usage": "1MiB / 1GiB", "mem_percent": 0.1},       # not in the list
                     CIDS[1]: {"cpu": "bad", "mem_usage": "1MiB / 1GiB", "mem_percent": 0.1},    # unusable
                     CIDS[2]: {"cpu": 0, "mem_usage": "nonsense", "mem_percent": 0}}, 5, 2.0, False)
    d = unraid.parse_stats(sample, {CIDS[0]: "app-1", CIDS[1]: "app-2", CIDS[2]: "app-3"}, now)
    assert d["containers"]["app-1"] == {"cpu": 12.35, "mem_percent": 9.77, "mem_used": 100 * 2 ** 20,
                                        "mem_limit": 2 ** 30, "sampled_at": now}
    assert "app-2" not in d["containers"] and d["containers"]["app-3"]["mem_used"] is None
    assert d["reported"] == 2 and d["sampled_at"] == now


def test_the_container_list_keeps_the_docker_id():
    d = unraid.parse_docker(load("docker")["data"])
    assert [c["id"] for c in d["containers"][:2]] == CIDS[:2] or {c["id"] for c in d["containers"]} == set(CIDS)
    assert unraid.parse_docker({"docker": {"containers": [{"names": ["/x"], "state": "RUNNING"}]}})["containers"][0]["id"] is None


# --- the poller ---------------------------------------------------------------------------------------------------

def test_a_poll_stores_a_reading_per_container(conn, cfg, fake):
    add(conn, cfg)
    assert poll_at(conn, cfg, fake, NOW) == 1
    snap = db.get_snapshot(conn, "tower", unraid.STATS)
    assert snap.ok and snap.error is None and snap.taken_at == NOW
    cs = snap.data["containers"]
    assert set(cs) == {f"app-{i}" for i in range(1, 13)}
    assert cs["app-1"] == {"cpu": 1.5, "mem_percent": 4.88, "mem_used": 100 * 2 ** 20, "mem_limit": 2 * 2 ** 30,
                           "sampled_at": NOW}
    assert snap.data["sampled_at"] == NOW and snap.data["reported"] == 12
    assert len(fake.sockets) == 1
    # Only the allowed subscription went out, on the same address as the queries, and no mutation anywhere.
    sent = [m for s in fake.sockets for m in s.sent]
    assert [m["payload"]["query"] for m in sent if m["type"] == "subscribe"] == [STATS_SUBSCRIPTION]
    assert "mutation" not in json.dumps(sent).lower() and "mutation" not in " ".join(fake.queries()).lower()


def test_the_sample_is_taken_each_poll_not_every_five_minutes(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    assert poll_at(conn, cfg, fake, NOW + 30) == 0 and len(fake.sockets) == 1       # not due
    assert poll_at(conn, cfg, fake, NOW + 60) == 1 and len(fake.sockets) == 2
    assert db.get_snapshot(conn, "tower", unraid.STATS).taken_at == NOW + 60


def test_a_failed_sample_keeps_the_last_reading_and_blocks_nothing(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    good = db.get_snapshot(conn, "tower", unraid.STATS).data
    fake.ws_fail = ConnectionRefusedError("refused")
    fake.set(unraid.Q_DOCKER, lambda d: d["docker"]["containers"][0].update(status="Up 2 hours"))
    assert poll_at(conn, cfg, fake, NOW + 60) == 1
    snap = db.get_snapshot(conn, "tower", unraid.STATS)
    assert not snap.ok and "connect" in snap.error.lower() and snap.data == good          # the old data, with its own age
    assert snap.data["sampled_at"] == NOW
    # The other sources and the poll itself went on.
    r = store.get(conn, "tower")
    assert r["last_ok"] == NOW + 60 and r["fails"] == 0
    assert db.get_snapshot(conn, "tower", "unraid_docker").data["containers"][0]["status"] == "Up 2 hours"
    assert db.get_snapshot(conn, "tower", "unraid_system").taken_at == NOW + 60
    # It recovers on the next good sample.
    fake.ws_fail = None
    poll_at(conn, cfg, fake, NOW + 120)
    snap = db.get_snapshot(conn, "tower", unraid.STATS)
    assert snap.ok and snap.data["sampled_at"] == NOW + 120


def test_a_sample_with_no_reports_is_a_failure_that_keeps_old_data(conn, cfg, fake):
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    fake.stats = []
    poll_at(conn, cfg, fake, NOW + 60)
    snap = db.get_snapshot(conn, "tower", unraid.STATS)
    assert not snap.ok and "no container statistics" in snap.error and snap.data["sampled_at"] == NOW


def test_a_slow_sample_does_not_hold_up_the_other_sources(conn, cfg, fake, monkeypatch):
    """The sample runs beside the remaining queries, and a limit ends it: with nothing to report it takes its
    whole time, and the poll still finishes with every other source stored."""
    monkeypatch.setattr(client, "SAMPLE_SECONDS", 0.6)
    fake.stats = fake.stats[:2]
    add(conn, cfg)
    t = time.monotonic()
    poll_at(conn, cfg, fake, NOW)
    assert 0.5 < time.monotonic() - t < 4
    assert set(db.get_snapshots(conn, "tower")) == set(unraid.SOURCES) | {unraid.STATS}
    assert db.get_snapshot(conn, "tower", unraid.STATS).data["reported"] == 2


def test_with_nothing_running_no_subscription_is_opened(conn, cfg, fake):
    def stop_all(d):
        for c_ in d["docker"]["containers"]:
            c_["state"] = "EXITED"
    fake.set(unraid.Q_DOCKER, stop_all)
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    assert fake.sockets == []
    snap = db.get_snapshot(conn, "tower", unraid.STATS)
    assert snap.ok and snap.data["containers"] == {}


def test_a_wrong_key_stops_the_poll_before_any_subscription(conn, cfg, fake):
    add(conn, cfg)
    fake.key = "something-else"
    poll_at(conn, cfg, fake, NOW)
    assert fake.sockets == [] and store.get(conn, "tower")["fails"] == 1


def test_readings_raise_no_findings(conn, cfg, fake):
    fake.stats = [stat(cid, 400.0, "1.9GiB / 2GiB", 99.0) for cid in CIDS]
    add(conn, cfg)
    poll_at(conn, cfg, fake, NOW)
    assert not [f for f in db.open_findings(conn, "tower") if "stat" in f["rule"] or "cpu" in f["rule"] or "mem" in f["rule"]]


def test_a_pinned_system_samples_with_the_stored_certificate(conn, cfg, fake, tmp_path):
    pem, _, _ = make_cert(tmp_path / "srv", "tower.test")
    fake.server_cert = pem
    add(conn, cfg, tls="pin", pin=fingerprint(pem), cert=pem)
    poll_at(conn, cfg, fake, NOW)
    assert db.get_snapshot(conn, "tower", unraid.STATS).ok and len(fake.sockets) == 1


# --- the pages -------------------------------------------------------------------------------------------------

def test_the_containers_page_has_cpu_and_memory_columns(polled):
    html = polled.get("/h/tower/containers").text
    assert '<th data-sort="num"><button type="button" class="ds-sort">CPU</button></th>' in html or \
        re.search(r'<th data-sort="num">(<button[^>]*>)?CPU', html)
    assert re.search(r'<th data-sort="num">(<button[^>]*>)?Memory', html)
    row = re.search(r'<tr id="ctr-app-1" data-row>(.*?)</tr>', html, re.S).group(1)
    assert 'data-v="1.5" data-label="CPU">1.5%</td>' in row
    assert f'data-v="{100 * 2 ** 20}" data-label="Memory">100 MiB' in row and "4.9% of 2.0 GiB" in row
    # Every cell keeps its label, the folders and the row anchors are still there, and the panels all resolve.
    cells = re.findall(r"<td[^>]*>", html)
    assert cells and all("data-label=" in t for t in cells)
    assert 'id="folder-' in html or "Ungrouped" in html or 'id="ctr-app-12"' in html
    assert check_panels(html) >= 2 and 'id="src-stats"' in html
    # The panel names the subscription and says how it is sampled; it is not offered as a curl query.
    assert STATS_SUBSCRIPTION in html and "Sampled for a few seconds every 60 s" in html
    assert "docker stats --no-stream" in html and "never a mutation" in html
    assert 'colspan="8"' in html or "ds-group-head" not in html
    assert "CPU and memory were sampled" in html and "100% is one core" in html


def test_a_stopped_container_has_no_reading_and_sorts_last(polled, hub_cfg, fake):
    def stop(d):
        d["docker"]["containers"][0]["state"] = "EXITED"
    fake.set(unraid.Q_DOCKER, stop)
    poll_now(hub_cfg, fake, time.time() + 61)
    html = polled.get("/h/tower/containers").text
    row = re.search(r'<tr id="ctr-app-1" data-row>(.*?)</tr>', html, re.S).group(1)
    assert 'data-v="" data-label="CPU">—</td>' in row and 'data-v="" data-label="Memory">—' in row


def test_no_memory_limit_is_said_plainly(polled, hub_cfg, fake):
    total = db.get_snapshot(conn_of(hub_cfg), "tower", "unraid_system").data["memory"]["total"]
    gib = total / 2 ** 30
    fake.stats[0] = stat(CIDS[0], 1.0, f"500MiB / {gib:.2f}GiB", 0.5)
    poll_now(hub_cfg, fake, time.time() + 61)
    html = polled.get("/h/tower/containers").text
    assert "of host memory, no limit" in html


def test_the_page_shows_the_age_and_the_error_of_a_stale_reading(polled, hub_cfg, fake):
    fake.ws_fail = OSError("no route")
    poll_now(hub_cfg, fake, time.time() + 61)
    html = polled.get("/h/tower/containers").text
    assert "the latest sample failed" in html and "no route" in html and "last good readings" in html
    assert 'data-label="CPU">1.5%</td>' in html          # the last good reading is still shown
    overview = polled.get("/h/tower/").text
    assert "The latest sample failed (Could not connect: no route)" in overview


def test_before_any_sample_the_page_says_so(c, hub_cfg, fake):
    fake.ws_fail = OSError("no route")
    save(c)
    poll_now(hub_cfg, fake, time.time())
    html = c.get("/h/tower/containers").text
    assert "CPU and memory could not be read: " in html and 'data-label="CPU">—</td>' in html
    assert "Top containers" not in c.get("/h/tower/").text


def test_the_overview_lists_the_top_five_by_cpu_and_by_memory(c, hub_cfg, fake):
    # CPU rises with the container number; memory falls.
    fake.stats = [stat(cid, float(n), f"{(13 - n) * 10}MiB / 2GiB", 1.0) for n, cid in enumerate(CIDS, 1)]
    save(c)
    poll_now(hub_cfg, fake, time.time())
    html = c.get("/h/tower/").text
    block = re.search(r'<section class="card" id="top-containers".*?</section>', html, re.S).group(0)
    by_cpu, by_mem = block.split("By memory")
    cpu_names = re.findall(r'href="/h/tower/containers#ctr-([^"]+)"', by_cpu)
    mem_names = re.findall(r'href="/h/tower/containers#ctr-([^"]+)"', by_mem)
    assert cpu_names == [f"app-{n}" for n in (12, 11, 10, 9, 8)]
    assert mem_names == [f"app-{n}" for n in (1, 2, 3, 4, 5)]
    assert "12.0%" in by_cpu and "120 MiB" in by_mem
    assert 'id="src-stats"' in html and check_panels(html) >= 4
    # The link lands on a row that the Containers page renders.
    page = c.get("/h/tower/containers").text
    for n in cpu_names + mem_names:
        assert f'id="ctr-{n}"' in page


def test_idle_containers_are_not_listed_by_cpu(c, hub_cfg, fake):
    fake.stats = [stat(cid, 0.0 if n > 2 else 5.0 - n, "10MiB / 2GiB", 1.0) for n, cid in enumerate(CIDS, 1)]
    save(c)
    poll_now(hub_cfg, fake, time.time())
    block = re.search(r'<section class="card" id="top-containers".*?</section>', c.get("/h/tower/").text, re.S).group(0)
    assert len(re.findall(r'href="[^"]*"', block.split("By memory")[0])) == 2
    partial = c.get("/h/tower/partials/overview").text
    assert "Top containers" in partial


def test_names_from_the_server_are_escaped_in_the_new_cells(c, hub_cfg, fake):
    evil = "<img src=x onerror=alert(1)>"
    fake.set(unraid.Q_DOCKER, lambda d: d["docker"]["containers"][0].update(names=["/" + evil]))
    save(c)
    poll_now(hub_cfg, fake, time.time())
    for path in ("/h/tower/containers", "/h/tower/"):
        assert "<img src=x" not in c.get(path).text
