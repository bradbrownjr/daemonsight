"""DaemonSight: a self-hosted security dashboard for your whole stack (Linux servers, containers, Unraid,
OPNsense): what each system exposes, what is watching it, and what is out of date."""

__version__ = "0.1.0"


def full_version() -> str:
    """The version plus the commit install.sh recorded next to the venv
    (/opt/daemonsight/REVISION), when there is one."""
    import sys
    from pathlib import Path

    try:
        rev = (Path(sys.prefix).parent / "REVISION").read_text().strip()
    except OSError:
        rev = ""
    return f"{__version__} ({rev})" if rev else __version__
