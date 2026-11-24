"""packaging/config.example.toml documents every setting and still loads."""

import re
from dataclasses import fields, is_dataclass
from pathlib import Path

from daemonsight import config

EXAMPLE = Path(__file__).resolve().parent.parent / "packaging" / "config.example.toml"

# Not settings: set by the hub, or read from the file for another reason.
NOT_SETTINGS = {"kind", "file_keys"}


def _sections(text: str) -> dict[str, str]:
    """Text of each section, "" for the top of the file."""
    out: dict[str, list[str]] = {"": []}
    cur = ""
    for line in text.splitlines():
        m = re.match(r"^#?\s*\[([a-z_.]+)\]\s*$", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def _settings(cls, prefix=""):
    for f in fields(cls):
        if f.name in NOT_SETTINGS:
            continue
        sub = f.default_factory() if callable(f.default_factory) else None
        if sub is not None and is_dataclass(sub):
            yield from _settings(type(sub), f"{prefix}{f.name}.")
        else:
            yield prefix.rstrip("."), f.name


def test_every_setting_is_in_the_example():
    sections = _sections(EXAMPLE.read_text())
    missing = []
    for section, key in _settings(config.Config):
        body = sections.get(section)
        if body is None and section:
            missing.append(f"[{section}] (section)")
            continue
        dotted = f"{section}.{key}" if section else key
        if dotted in sections:   # a table setting: its own [section] or [links]
            continue
        if not re.search(rf"^#?\s*{re.escape(key)}\s*=", body or "", re.M):
            missing.append(f"{section}.{key}" if section else key)
    assert not missing, f"not in packaging/config.example.toml: {missing}"


def test_example_has_no_unknown_settings():
    """Every `# key = value` line names a real setting in its section."""
    known = {(s, k) for s, k in _settings(config.Config)}
    known.add(("collector", "metrics_retention_hours"))
    stale = []
    cur = ""
    for line in EXAMPLE.read_text().splitlines():
        m = re.match(r"^#?\s*\[([a-z_.]+)\]\s*$", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"^# ([a-z_][a-z0-9_]*) = ", line)
        if m and cur not in ("links", "exposure.jail_covers") and (cur, m.group(1)) not in known:
            stale.append(f"{cur}.{m.group(1)}")
    assert not stale, f"not settings any more: {stale}"


def test_example_loads_with_every_line_switched_on(tmp_path):
    out = []
    for line in EXAMPLE.read_text().splitlines():
        m = re.match(r"^# ([a-z_][a-z0-9_]* = .*)$", line)
        h = re.match(r"^# (\[[a-z_.]+\])\s*$", line)
        out.append(m.group(1) if m else h.group(1) if h else line)
    path = tmp_path / "config.toml"
    path.write_text("\n".join(out) + "\n")
    cfg = config.load(path)
    assert cfg.upload.url.startswith("https://")
    assert cfg.web.port == 8466
    assert config.load(EXAMPLE).web.port == 8466   # the file as shipped
