import json
from urllib import error, request

from app.config import get_settings


def send_verification_email(*, to_email: str, verification_code: str, plan: str) -> None:
    settings = get_settings()
    if not settings.sendgrid_api_key:
        raise RuntimeError("Email delivery is not configured.")

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
        with request.urlopen(req) as response:
            if response.status >= 400:
                raise RuntimeError(f"Email delivery failed with HTTP {response.status}")
    except error.HTTPError as exc:
        raise RuntimeError(f"Email delivery failed with HTTP {exc.code}") from exc
    except error.URLError as exc:
        raise RuntimeError("Email delivery request failed") from exc
