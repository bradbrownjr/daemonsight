import os

import pytest

from daemonsight.collector.sources.systemd import UINT64_MAX, SystemdSource, merge_props, parse_unit_row

ROW = ("backup.service", "Nightly backup", "loaded", "failed", "failed", "",
       "/org/freedesktop/systemd1/unit/backup_2eservice", 0, "", "/")


def test_parse_row():
    u = parse_unit_row(ROW)
    assert u["name"] == "backup.service"
    assert u["active"] == "failed"
    assert u["path"].endswith("backup_2eservice")


def test_merge_props_treats_uint64_max_as_unset():
    u = merge_props(parse_unit_row(ROW),
                    {"ActiveEnterTimestamp": 1_700_000_000_000_000, "InactiveEnterTimestamp": 1_700_000_100_000_000},
                    {"NRestarts": 0, "MemoryCurrent": UINT64_MAX, "CPUUsageNSec": UINT64_MAX,
                     "MainPID": 0, "Result": "exit-code", "ControlGroup": ""})
    assert u["memory"] is None
    assert u["cpu_ns"] is None
    assert u["main_pid"] is None
    assert u["result"] == "exit-code"
    # A failed unit shows when it stopped, not when it last started.
    assert u["since"] == 1_700_000_100.0


@pytest.mark.skipif(not os.path.exists("/run/dbus/system_bus_socket"), reason="no system D-Bus")
async def test_live_system_bus():
    src = SystemdSource(patterns=["*.service"])
    try:
        data = await src.collect()
    finally:
        await src.close()
    assert data["units"]
    assert all(u["name"].endswith(".service") or u["active"] == "failed" for u in data["units"])
    assert sum(data["counts"].values()) == len(data["units"])
