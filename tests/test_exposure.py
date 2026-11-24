"""Whether a system is publicly exposed (cve/exposure.py), the first input of CISA BOD 26-04's table: a collector host, the firewall,
a container image with and without a port forward, and a system with no exposure data at a private and at a public address."""

import time

from daemonsight import db, hub
from daemonsight.cve import exposure, priority
from daemonsight.web import views

from .test_hub import body, post
from .test_opnsense import _added, app_client, c, conn_of, fake, hub_cfg  # noqa: F401 (fixtures)

FW_IP = "10.20.0.8"        # the address the fixture firewall's port forwards lead to (tests/fixtures/opnsense/nat.json)


def add_host(c, hub_cfg, name, ports=None, address=None):
    conn = conn_of(hub_cfg)
    token = hub.add_host(conn, name)
    snaps = [{"source": "ports", "taken_at": time.time(), "ok": True, "data": ports}] if ports else []
    assert post(c, body(host=name, snapshots=snaps), token).status_code in (200, 202, 204)
    if address:
        conn.execute("UPDATE hosts SET address = ? WHERE id = ?", (address, name))
    return conn


def listener(port, scope, addrs, proto="tcp", process="nginx"):
    return {"proto": proto, "port": port, "addresses": addrs, "scope": scope, "pid": 1, "process": process,
            "owner": {"kind": "unit", "id": process + ".service"}}


def decide(conn, hub_cfg, host):
    return exposure.host_exposure(conn, views.host_config(conn, hub_cfg, host), host)


def test_a_host_the_firewall_forwards_to_is_exposed_and_the_evidence_names_the_forward(c, hub_cfg, fake):
    ports = {"listeners": [listener(80, "private", [FW_IP])], "addresses": [{"ip": FW_IP, "iface": "eth0", "scope": "private"}]}
    conn = add_host(c, hub_cfg, "web", ports)
    assert decide(conn, hub_cfg, "web") == exposure.Exposure(False, "no listener is reachable from the internet and no firewall forward leads to it")
    _added(c, hub_cfg, fake)                                      # the hub now reads the firewall and its forwards
    e = decide(conn, hub_cfg, "web")
    assert e.exposed and e.data and e.label == "public"
    assert "port 80/tcp is reached from the internet through forward 'Web server' on fw1" in e.why


def test_a_host_on_the_lan_that_nothing_forwards_to_is_internal(c, hub_cfg, fake):
    ports = {"listeners": [listener(22, "private", ["10.20.0.99"], process="sshd")],
             "addresses": [{"ip": "10.20.0.99", "iface": "eth0", "scope": "private"}]}
    conn = add_host(c, hub_cfg, "lan", ports)
    _added(c, hub_cfg, fake)
    e = decide(conn, hub_cfg, "lan")
    assert not e.exposed and e.label == "internal" and e.data


def test_a_public_address_with_a_listener_the_host_firewall_lets_through_is_exposed(c, hub_cfg, fake):
    pub = {"ip": "203.0.113.9", "iface": "eth0", "scope": "public"}
    ports = {"listeners": [listener(443, "all", ["0.0.0.0", "::"]), listener(5432, "loopback", ["127.0.0.1"], process="postgres")],
             "addresses": [pub]}
    conn = add_host(c, hub_cfg, "vps", ports)
    e = decide(conn, hub_cfg, "vps")
    assert e.exposed and "port 443/tcp (nginx) listens on a public address and the host firewall lets it through" in e.why
    # The provider's allow list can leave it out: then the public address alone is not exposure.
    cfg_host = views.host_config(conn, hub_cfg, "vps")
    cfg_host.exposure.upstream_allow = ["22/tcp"]
    assert not exposure.host_exposure(conn, cfg_host, "vps").exposed


def test_a_public_address_with_only_local_listeners_is_not_exposed(c, hub_cfg, fake):
    ports = {"listeners": [listener(5432, "loopback", ["127.0.0.1"], process="postgres")],
             "addresses": [{"ip": "203.0.113.9", "iface": "eth0", "scope": "public"}]}
    conn = add_host(c, hub_cfg, "quiet", ports)
    e = decide(conn, hub_cfg, "quiet")
    assert not e.exposed and "has a public address, but no listener" in e.why


def test_without_exposure_data_a_public_address_decides_and_a_private_one_does_not(c, hub_cfg, fake):
    conn = add_host(c, hub_cfg, "noports", None, address="203.0.113.7")
    e = decide(conn, hub_cfg, "noports")
    assert e.exposed and not e.data and "203.0.113.7 is publicly routable (exposure data is missing)" in e.why
    conn = add_host(c, hub_cfg, "private", None, address="10.0.0.5")
    e = decide(conn, hub_cfg, "private")
    assert not e.exposed and not e.data and "no publicly routable address" in e.why
    assert not exposure.unknown([None]).exposed and exposure.unknown(["2001:db8::1"]).exposed      # IPv6 counts too
    assert not exposure.unknown(["192.168.1.2", "100.64.0.3", "fd00::1"]).exposed                   # private, CGNAT and ULA do not


def test_a_firewall_is_always_exposed():
    e = exposure.firewall_exposure()
    assert e.exposed and not e.data and "network device" in e.why
    r = priority.rate({"kev": False, "epss": 0.0}, e.exposed, 0.04)
    assert r.exposed and r.row == 8 and r.days == 60       # exposed, not in KEV, not automatable, partial


# --- container images ------------------------------------------------------------------------------------------------------------

def unraid(conn, url):
    conn.execute("INSERT INTO hosts (id, token_hash, created_at, kind) VALUES ('tower', 'x', 0, 'unraid')")
    conn.execute("INSERT INTO remotes (id, kind, url, created_at) VALUES ('tower', 'unraid', ?, 0)", (url,))


def summary(images):
    """The stored Docker summary of one system: {image id: [container names]} -> containers and image_packages."""
    return {"image_packages": [{"image_id": i} for i in images],
            "containers": [{"name": n, "image_id": i, "state": "running"} for i, names in images.items() for n in names]}


def published(**by_name):
    return {"containers": [{"name": n, "ports": [{"ip": "0.0.0.0", "private": p, "public": p, "type": "TCP"} for p in ports]}
                           for n, ports in by_name.items()]}


def test_an_image_is_exposed_when_a_container_publishes_a_port_the_firewall_forwards(c, hub_cfg, fake):
    conn = conn_of(hub_cfg)
    unraid(conn, f"https://{FW_IP}")
    _added(c, hub_cfg, fake)
    imgs = {"sha256:aa": ["web"], "sha256:bb": ["db"], "sha256:cc": ["sidecar"], "sha256:dd": []}
    got = exposure.image_exposures(conn, "tower", summary(imgs), published(web=[80], db=[5432], sidecar=[]))
    assert got["sha256:aa"].exposed and "port 80/tcp of container web is reached from the internet through forward 'Web server' on fw1" in got["sha256:aa"].why
    assert not got["sha256:bb"].exposed and got["sha256:bb"].data and "no firewall port forward or Caddy site leads to its published ports (5432/tcp)" in got["sha256:bb"].why
    assert not got["sha256:cc"].exposed and "publish no port" in got["sha256:cc"].why and not got["sha256:cc"].data
    assert not got["sha256:dd"].exposed and "no running container uses it" in got["sha256:dd"].why


def test_a_stopped_container_or_a_port_bound_to_another_address_does_not_expose_the_image(c, hub_cfg, fake):
    conn = conn_of(hub_cfg)
    unraid(conn, f"https://{FW_IP}")
    _added(c, hub_cfg, fake)
    data = summary({"sha256:aa": ["web"]})
    data["containers"][0]["state"] = "exited"
    assert not exposure.image_exposures(conn, "tower", data, published(web=[80]))["sha256:aa"].exposed
    bound = {"containers": [{"name": "web", "ports": [{"ip": "127.0.0.1", "private": 80, "public": 80, "type": "TCP"}]}]}
    assert not exposure.image_exposures(conn, "tower", summary({"sha256:aa": ["web"]}), bound)["sha256:aa"].exposed


def test_without_a_firewall_link_the_systems_address_decides(c, hub_cfg, fake):
    imgs = {"sha256:aa": ["web"]}
    conn = conn_of(hub_cfg)
    unraid(conn, "https://203.0.113.20")                  # a publicly routable address: the container's published port is reachable
    e = exposure.image_exposures(conn, "tower", summary(imgs), published(web=[8080]))["sha256:aa"]
    assert e.exposed and not e.data and "203.0.113.20, which is publicly routable" in e.why
    conn.execute("UPDATE remotes SET url = 'https://192.168.1.2' WHERE id = 'tower'")   # private, and no firewall is read: internal
    e = exposure.image_exposures(conn, "tower", summary(imgs), published(web=[8080]))["sha256:aa"]
    assert not e.exposed and "no firewall port forward or Caddy site leads to its published ports (8080/tcp)" in e.why
    conn.execute("UPDATE remotes SET url = 'https://tower.example.lan' WHERE id = 'tower'")   # a name: no forward can be matched
    e = exposure.image_exposures(conn, "tower", summary(imgs), published(web=[8080]))["sha256:aa"]
    assert not e.exposed and not e.data and "address is a name" in e.why


def test_the_exposure_changes_the_rating_of_the_same_cve():
    cve = {"kev": True, "epss": 0.5, "automatable": "yes", "impact": "total"}
    assert priority.rate(cve, True, 0.04).row == 1 and priority.rate(cve, False, 0.04).row == 9
