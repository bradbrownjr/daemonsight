"""Email through a fake SMTP server: implicit TLS and STARTTLS under a verified context, never AUTH or mail in the clear, the
inline logo, and what an administrator sees when it fails."""

import ssl
from email import message_from_bytes, policy

import pytest

from daemonsight import db, notify
from daemonsight.notify import channels, engine, render, send

from .fake_notify import Fake, FakeNet, FakeSMTP, make_cert
from .test_notify import NY, T0, F, add_channel, alert_note, cfg, conn, many, put  # noqa: F401 (fixtures)


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    c = make_cert(tmp_path_factory.mktemp("smtp"))
    if c is None:
        pytest.skip("openssl is not installed")
    return c


@pytest.fixture
def trusting(cert, monkeypatch):
    """The sender's context, as it is in production (CERT_REQUIRED, host name checked), but trusting the test certificate."""
    monkeypatch.setattr(send, "tls_context", lambda: ssl.create_default_context(cafile=str(cert[1])))


def channel(server: FakeSMTP, security="tls", user="bot", **over) -> dict:
    cfg = {"host": "localhost", "port": server.port, "security": security, "user": user, "from": "ds@example.com",
           "to": ["a@example.com", "b@example.com"]}
    cfg.update(over)
    return {"id": 7, "kind": "email", "config": cfg}


def test_the_default_context_verifies_certificates_and_names():
    ctx = send.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


@pytest.mark.parametrize("mode, security", [("tls", "tls"), ("starttls", "starttls")])
async def test_mail_goes_out_encrypted_with_the_login_after_encryption(cert, trusting, mode, security):
    srv = FakeSMTP(mode, cert)
    try:
        await send.send(channel(srv, security), "pw-secret-1", alert_note(many(3)), FakeNet(Fake()))
        assert srv.auth_log == [("bot", True, True)]                        # the login happened, over TLS
        assert len(srv.messages) == 1 and srv.recipients == [["a@example.com", "b@example.com"]]
        parsed = message_from_bytes(srv.messages[0], policy=policy.default)
        assert parsed["From"] == "ds@example.com" and parsed["Subject"].startswith("DaemonSight: 3 new")
        assert parsed.get_content_type() == "multipart/alternative"
        html_part = parsed.get_payload()[1]
        assert html_part.get_content_type() == "multipart/related"          # the logo travels with the message, by Content-ID
        assert html_part.get_payload()[1].get_content_type() == "image/png"
        if mode == "starttls":
            assert all(c in ("EHLO", "STARTTLS") for c in srv.clear_commands)   # nothing but the handshake was sent in the clear
    finally:
        srv.close()


async def test_a_certificate_that_is_not_trusted_stops_everything(cert):
    srv = FakeSMTP("tls", cert)               # the real default context does not know this self-signed certificate
    try:
        with pytest.raises(send.SendError) as e:
            await send.send(channel(srv), "pw-secret-1", alert_note(many(1)), FakeNet(Fake()))
        assert "certificate" in e.value.message and "pw-secret-1" not in e.value.message
        assert srv.auth_log == [] and srv.messages == []                   # no login, no mail
    finally:
        srv.close()


async def test_a_starttls_certificate_that_is_not_trusted_sends_no_login(cert):
    srv = FakeSMTP("starttls", cert)
    try:
        with pytest.raises(send.SendError) as e:
            await send.send(channel(srv, "starttls"), "pw-secret-1", alert_note(many(1)), FakeNet(Fake()))
        assert "certificate" in e.value.message
        assert srv.auth_log == [] and srv.messages == []
    finally:
        srv.close()


async def test_a_server_without_starttls_is_refused_and_nothing_is_sent(cert, trusting):
    srv = FakeSMTP("starttls", cert, offer_starttls=False)
    try:
        with pytest.raises(send.SendError) as e:
            await send.send(channel(srv, "starttls"), "pw-secret-1", alert_note(many(1)), FakeNet(Fake()))
        assert "STARTTLS" in e.value.message and e.value.permanent
        assert srv.auth_log == [] and srv.messages == []
    finally:
        srv.close()


async def test_an_unencrypted_server_never_sees_the_password(trusting):
    srv = FakeSMTP("plain")                    # advertises AUTH with no TLS at all
    try:
        with pytest.raises(send.SendError):
            await send.send(channel(srv, "starttls"), "pw-secret-1", alert_note(many(1)), FakeNet(Fake()))
        with pytest.raises(send.SendError):    # implicit TLS against a plain server: the handshake fails
            await send.send(channel(srv, "tls"), "pw-secret-1", alert_note(many(1)), FakeNet(Fake()))
        assert srv.auth_log == [] and srv.messages == []
    finally:
        srv.close()


async def test_a_wrong_password_is_reported_without_it(cert, trusting):
    srv = FakeSMTP("tls", cert)
    try:
        with pytest.raises(send.SendError) as e:
            await send.send(channel(srv), "not-the-password", alert_note(many(1)), FakeNet(Fake()))
        assert "refused the login" in e.value.message and "535" in e.value.message and "not-the-password" not in e.value.message
        assert e.value.permanent
    finally:
        srv.close()


async def test_a_server_that_needs_no_login(cert, trusting):
    srv = FakeSMTP("tls", cert)
    try:
        await send.send(channel(srv, user=""), None, alert_note(many(1)), FakeNet(Fake()))
        assert srv.auth_log == [] and len(srv.messages) == 1
    finally:
        srv.close()


async def test_an_email_channel_end_to_end_through_the_outbox(cert, trusting, conn, cfg):
    srv = FakeSMTP("tls", cert)
    try:
        add_channel(conn, cfg, "email", email_port=str(srv.port))
        put(conn, [F("openssl", "critical", days=3)], T0)
        engine.scan(conn, T0)
        assert await engine.deliver(conn, cfg, T0 + 20, FakeNet(Fake()), NY) == 1
        assert len(srv.messages) == 1
        body = message_from_bytes(srv.messages[0], policy=policy.default)
        assert "openssl" in body.get_payload()[0].get_content()
        ch = channels.all_channels(conn)[0]
        assert ch["last_ok"] and not ch["last_error"]
    finally:
        srv.close()


async def test_email_failures_show_on_the_channel_without_the_password(cert, conn, cfg):
    srv = FakeSMTP("tls", cert)               # not trusting: the certificate check fails
    try:
        add_channel(conn, cfg, "email", email_port=str(srv.port))
        put(conn, [F("openssl", "critical")], T0)
        engine.scan(conn, T0)
        await engine.deliver(conn, cfg, T0 + 20, FakeNet(Fake()), NY)
        ch = channels.all_channels(conn)[0]
        assert "certificate" in ch["last_error"] and "pw-secret-1" not in str(dict(ch))
    finally:
        srv.close()


def test_the_form_never_offers_unencrypted_mail():
    assert [v for v, _l in channels.EMAIL_SECURITY] == ["tls", "starttls"]
    from .test_notify import form
    for bad in ("none", "plain", "ssl", ""):
        _v, _s, _d, errors = channels.parse_form(form("email", email_security=bad), None, secret_saved_now=False)
        assert "email_security" in errors
