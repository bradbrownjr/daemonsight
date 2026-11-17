"""Docker parsing. Field names and formats follow the Engine API v1.47 spec."""

import struct

from daemonsight.collector.sources.docker import (
    cpu_percent, demux, mask_secrets, memory_used, published_ports, summarize,
)


def frame(stream: int, text: str) -> bytes:
    data = text.encode()
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(data)) + data


def test_demux_splits_frames_across_streams():
    raw = frame(1, "one\ntwo\n") + frame(2, "err\n") + frame(1, "three")
    assert demux(raw) == ["one", "two", "err", "three"]


def test_demux_falls_back_to_raw_text():
    assert demux(b"plain line\nanother\n") == ["plain line", "another"]


def test_cpu_percent_uses_spec_formula():
    stats = {
        "cpu_stats": {"cpu_usage": {"total_usage": 2_000_000}, "system_cpu_usage": 20_000_000, "online_cpus": 4},
        "precpu_stats": {"cpu_usage": {"total_usage": 1_000_000}, "system_cpu_usage": 10_000_000},
    }
    # (1e6 / 1e7) * 4 * 100
    assert cpu_percent(stats) == 40.0


def test_cpu_percent_missing_previous_sample():
    stats = {"cpu_stats": {"cpu_usage": {"total_usage": 5}, "system_cpu_usage": 10, "online_cpus": 1},
             "precpu_stats": {"cpu_usage": {"total_usage": 0}}}
    assert cpu_percent(stats) is None


def test_memory_used_cgroup_v2_and_v1():
    assert memory_used({"memory_stats": {"usage": 1000, "stats": {"inactive_file": 300}}}) == 700
    assert memory_used({"memory_stats": {"usage": 1000, "stats": {"cache": 100}}}) == 900
    assert memory_used({"memory_stats": {}}) is None


def test_published_ports_dedupes_and_defaults_ip():
    inspect = {"NetworkSettings": {"Ports": {
        "5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}, {"HostIp": "::", "HostPort": "5432"},
                     {"HostIp": "0.0.0.0", "HostPort": "5432"}],
        "6379/tcp": None,
        "53/udp": [{"HostIp": "", "HostPort": "5353"}],
    }}}
    ports = published_ports(inspect)
    assert {"host_ip": "0.0.0.0", "host_port": 5432, "container_port": 5432, "proto": "tcp"} in ports
    assert {"host_ip": "::", "host_port": 5432, "container_port": 5432, "proto": "tcp"} in ports
    assert {"host_ip": "0.0.0.0", "host_port": 5353, "container_port": 53, "proto": "udp"} in ports
    assert len(ports) == 3


def test_mask_secrets():
    assert mask_secrets("connecting with password=hunter2 now") == "connecting with password=*** now"
    assert mask_secrets("Authorization: Bearer abc.def") == "Authorization: Bearer ***"
    assert mask_secrets("postgres://app:s3cret@db:5432/app") == "postgres://app:***@db:5432/app"
    assert mask_secrets("ordinary line") == "ordinary line"


def test_summarize_exited_oom():
    inspect = {
        "Id": "a" * 64, "Name": "/status",
        "Config": {"Image": "louislam/uptime-kuma:1", "Labels": {"com.docker.compose.project": "mon"}},
        "State": {"Status": "exited", "ExitCode": 137, "OOMKilled": True,
                  "StartedAt": "2026-11-15T01:00:00Z", "FinishedAt": "2026-11-15T03:59:40Z"},
        "RestartCount": 0, "HostConfig": {"RestartPolicy": {"Name": ""}},
        "NetworkSettings": {"Ports": {}},
    }
    c = summarize(inspect, None, ["line"])
    assert c["name"] == "status"
    assert c["oom_killed"] is True
    assert c["exit_code"] == 137
    assert c["health"] == "none"
    assert c["restart_policy"] == "no"
    assert c["project"] == "mon"
