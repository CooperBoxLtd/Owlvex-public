import json
from urllib import error, request

from app.config import get_settings


def _extract_sendgrid_error_detail(exc: error.HTTPError) -> str:
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

    errors_payload = payload.get("errors")
    if isinstance(errors_payload, list) and errors_payload:
        messages = []
        for item in errors_payload:
            if not isinstance(item, dict):
                continue
            message = str(item.get("message", "")).strip()
            field = str(item.get("field", "")).strip()
            if message and field:
                messages.append(f"{field}: {message}")
            elif message:
                messages.append(message)
        if messages:
            return f"Email delivery failed with HTTP {exc.code}: {'; '.join(messages[:3])}"

    snippet = raw_body.replace("\n", " ").strip()[:240]
    return f"Email delivery failed with HTTP {exc.code}: {snippet}"


def send_verification_email(*, to_email: str, verification_code: str, plan: str) -> None:
    settings = get_settings()
    if not settings.sendgrid_api_key:
        raise RuntimeError("Email delivery is not configured.")
    if not settings.from_email or "@" not in settings.from_email:
        raise RuntimeError("Email delivery is misconfigured: FROM_EMAIL must be set to a valid sender address.")

    subject = "Your Owlvex verification code"
    body = (
        f"Your Owlvex {plan} verification code is: {verification_code}\n\n"
        f"It expires in {settings.email_verification_code_minutes} minutes.\n"
        "Enter this code in the Owlvex extension to finish registration."
    )

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": settings.from_email},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }

    req = request.Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {settings.sendgrid_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=10) as response:
            if response.status >= 400:
                raise RuntimeError(f"Email delivery failed with HTTP {response.status}")
    except error.HTTPError as exc:
        raise RuntimeError(_extract_sendgrid_error_detail(exc)) from exc
    except error.URLError as exc:
        raise RuntimeError(f"Email delivery request failed: {exc.reason}") from exc
