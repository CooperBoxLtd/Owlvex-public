import io
import json
from urllib import error

from app.config import Settings
from app.services import email_service


def test_send_verification_email_posts_to_resend(monkeypatch):
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="re_test",
        from_email="verified-sender@example.com",
        environment="test",
    )
    monkeypatch.setattr(email_service, "get_settings", lambda: settings)

    captured = {}

    class _Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(email_service.request, "urlopen", fake_urlopen)

    email_service.send_verification_email(
        to_email="user@example.com",
        verification_code="123456",
        plan="trial",
    )

    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["timeout"] == 10
    assert captured["headers"]["Authorization"] == "Bearer re_test"
    assert captured["body"]["from"] == "verified-sender@example.com"
    assert captured["body"]["to"] == ["user@example.com"]
    assert "123456" in captured["body"]["text"]


def test_send_verification_email_surfaces_resend_error_detail(monkeypatch):
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="re_test",
        from_email="noreply@example.com",
        environment="test",
    )
    monkeypatch.setattr(email_service, "get_settings", lambda: settings)

    def fake_urlopen(req, timeout=0):
        raise error.HTTPError(
            req.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(json.dumps({
                "name": "validation_error",
                "message": "The from address does not match a verified domain."
            }).encode("utf-8")),
        )

    monkeypatch.setattr(email_service.request, "urlopen", fake_urlopen)

    try:
        email_service.send_verification_email(
            to_email="user@example.com",
            verification_code="123456",
            plan="trial",
        )
        assert False, "Expected send_verification_email to raise RuntimeError"
    except RuntimeError as exc:
        message = str(exc)
        assert "HTTP 403" in message
        assert "validation_error" in message
        assert "verified domain" in message
