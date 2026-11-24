import pytest

from daemonsight.config import Config
from daemonsight.web.auth import hash_password

PASSWORD = "correct horse battery"


@pytest.fixture
def cfg(tmp_path):
    c = Config(host_id="testhost", data_dir=str(tmp_path / "data"))
    c.web.password_file = str(tmp_path / "password")
    c.web.secret_file = str(tmp_path / "secret")
    (tmp_path / "password").write_text(hash_password(PASSWORD))
    (tmp_path / "secret").write_text("x" * 64)
    return c


@pytest.fixture(autouse=True)
def _no_advisory_spacing(monkeypatch):
    """The hub waits between two requests for an OPNsense advisory (cve/advisories.py `SPACING`); tests do not."""
    from daemonsight.cve import advisories
    monkeypatch.setattr(advisories, "SPACING", {advisories.SA_HOST: 0.0, advisories.GH_HOST: 0.0})


@pytest.fixture(autouse=True)
def _no_priority_fetch(request, monkeypatch):
    """The CVE chore asks raw.githubusercontent.com for a newer prioritisation table once a day (cve/priority_fetch.py); the
    chore tests' fake servers know nothing of it. tests/test_priority_fetch.py tests it for real."""
    if request.module.__name__.endswith("test_priority_fetch"):
        return
    from daemonsight.cve import run

    async def nothing(self, now):
        return None
    monkeypatch.setattr(run.Chore, "_fetch_priority", nothing)
