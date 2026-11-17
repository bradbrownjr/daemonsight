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
