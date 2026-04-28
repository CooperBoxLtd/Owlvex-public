import json
import socket
from urllib import error, request

from app.config import get_settings


def _extract_resend_error_detail(exc: error.HTTPError) -> str:
    try:
        raw_body = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        raw_body = ""

    if not raw_body:
        return f"Email delivery failed with HTTP {exc.code}"

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        snippet = raw_body.replace("\n", " ").strip()[:240]
        return f"Email delivery failed with HTTP {exc.code}: {snippet}"

    message = str(payload.get("message", "")).strip()
    name = str(payload.get("name", "")).strip()
    if message and name:
        return f"Email delivery failed with HTTP {exc.code}: {name}: {message}"
    if message:
        return f"Email delivery failed with HTTP {exc.code}: {message}"

    snippet = raw_body.replace("\n", " ").strip()[:240]
    return f"Email delivery failed with HTTP {exc.code}: {snippet}"


def _send_email(*, to_email: str, subject: str, text: str, html: str | None = None) -> None:
    settings = get_settings()
    if not settings.resend_api_key:
        raise RuntimeError("Email delivery is not configured.")
    if not settings.from_email or "@" not in settings.from_email:
        raise RuntimeError("Email delivery is misconfigured: FROM_EMAIL must be set to a valid sender address.")

    payload = {
        "from": settings.from_email,
        "to": [to_email],
        "subject": subject,
        "text": text,
    }
    if html:
        payload["html"] = html

    req = request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {settings.resend_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "owlvex-backend/1.0",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=settings.email_delivery_timeout_seconds) as response:
            if response.status >= 400:
                raise RuntimeError(f"Email delivery failed with HTTP {response.status}")
    except error.HTTPError as exc:
        raise RuntimeError(_extract_resend_error_detail(exc)) from exc
    except error.URLError as exc:
        raise RuntimeError(f"Email delivery request failed: {exc.reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError("Email delivery request timed out") from exc
    except OSError as exc:
        raise RuntimeError(f"Email delivery request failed: {exc}") from exc


def send_verification_email(*, to_email: str, verification_code: str, plan: str) -> None:
    settings = get_settings()
    subject = "Your Owlvex verification code"
    text = (
        f"Your Owlvex {plan} verification code is: {verification_code}\n\n"
        f"It expires in {settings.email_verification_code_minutes} minutes.\n"
        "Enter this code in the Owlvex extension to finish registration."
    )
    _send_email(to_email=to_email, subject=subject, text=text)


def send_licence_issued_email(
    *,
    to_email: str,
    team_name: str,
    plan: str,
    expires_at: str | None = None,
) -> None:
    subject = "Your Owlvex access is active"
    expiry_line = f"\nTrial expires at: {expires_at}\n" if expires_at else "\n"
    text = (
        f"Hi {team_name},\n\n"
        f"Thank you for registering for Owlvex ({plan} plan).\n"
        "Your access is now active in the Owlvex extension.\n"
        f"{expiry_line}\n"
        "You do not need to enter a licence key manually if you completed verification in the extension.\n\n"
        "If you need help restoring access later, contact support or use the Owlvex customer operations tools."
    )
    html = (
        "<h2>Your Owlvex access is active</h2>"
        f"<p>Hi {team_name},</p>"
        f"<p>Thank you for registering for Owlvex ({plan} plan).</p>"
        "<p>Your access is now active in the Owlvex extension.</p>"
        + (f"<p>Trial expires at: {expires_at}</p>" if expires_at else "")
        + "<p>You do not need to enter a licence key manually if you completed verification in the extension.</p>"
        "<p>If you need help restoring access later, contact support or use the Owlvex customer operations tools.</p>"
    )
    _send_email(to_email=to_email, subject=subject, text=text, html=html)
