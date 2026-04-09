import stripe
import hashlib
import logging
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

import sendgrid
from sendgrid.helpers.mail import Mail

from app.db.session import get_db
from app.db.models import Licence
from app.services.licence_service import generate_licence_key, hash_licence_key
from app.routers.licences import PLAN_FEATURES
from app.config import get_settings

router = APIRouter(prefix="/v1/billing", tags=["billing"])
settings = get_settings()
logger = logging.getLogger(__name__)


@router.post("/webhook/stripe")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    stripe_signature: str = Header(..., alias="Stripe-Signature"),
):
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature")
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook processing failed")

    event_type = event["type"]
    data = event["data"]["object"]

    try:
        if event_type == "checkout.session.completed":
            await _handle_checkout_completed(db, data)

        elif event_type == "customer.subscription.updated":
            await _handle_subscription_updated(db, data)

        elif event_type == "customer.subscription.deleted":
            await _handle_subscription_deleted(db, data)

        elif event_type == "invoice.payment_failed":
            logger.warning(f"Payment failed for customer {data.get('customer')} - Stripe handling retries")

        else:
            logger.debug(f"Unhandled Stripe event: {event_type}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing Stripe event {event_type}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Webhook processing failed")

    return {"received": True}


async def _handle_checkout_completed(db: AsyncSession, session: dict) -> None:
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")
    customer_email = session.get("customer_details", {}).get("email", "")
    metadata = session.get("metadata", {})

    plan = metadata.get("plan", "developer")
    seats = int(metadata.get("seats", 1))
    team_name = metadata.get("team_name", customer_email)

    raw_key = generate_licence_key()
    key_hash = hash_licence_key(raw_key)

    licence = Licence(
        licence_key_hash=key_hash,
        team_name=team_name,
        email=customer_email,
        plan=plan,
        seats=seats,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        features=PLAN_FEATURES.get(plan, PLAN_FEATURES["developer"]),
        is_active=True,
    )
    db.add(licence)
    await db.commit()

    logger.info(f"New licence created for {customer_email} (plan={plan}). Key: {raw_key}")
    await _send_licence_email(customer_email, team_name, plan, raw_key)


async def _send_licence_email(email: str, team_name: str, plan: str, raw_key: str) -> None:
    if not settings.sendgrid_api_key:
        logger.warning("SendGrid API key not configured — licence key not emailed")
        return

    body = f"""<h2>Your Owlvex licence key</h2>
<p>Hi {team_name},</p>
<p>Thank you for subscribing to Owlvex ({plan} plan). Your licence key is below.</p>
<p style="font-family:monospace;font-size:16px;background:#f4f4f4;padding:12px;border-radius:4px;">{raw_key}</p>
<p>To activate:</p>
<ol>
  <li>Open VS Code</li>
  <li>Open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P)</li>
  <li>Run <strong>Owlvex: Enter Licence Key</strong></li>
  <li>Paste your key</li>
</ol>
<p>Keep this email — the key cannot be retrieved again. If you lose it, contact support.</p>
<p>— The Owlvex team</p>"""

    message = Mail(
        from_email=settings.from_email,
        to_emails=email,
        subject="Your Owlvex licence key",
        html_content=body,
    )

    try:
        sg = sendgrid.SendGridAPIClient(api_key=settings.sendgrid_api_key)
        response = sg.send(message)
        logger.info(f"Licence email sent to {email} (status {response.status_code})")
    except Exception as e:
        logger.error(f"Failed to send licence email to {email}: {e}")
        # Do not raise — licence is already created; email failure is non-fatal


async def _handle_subscription_updated(db: AsyncSession, subscription: dict) -> None:
    customer_id = subscription.get("customer")
    new_plan = _plan_from_stripe_items(subscription)
    seats = subscription.get("quantity", 1)

    if not new_plan:
        return

    await db.execute(
        update(Licence)
        .where(Licence.stripe_customer_id == customer_id)
        .values(
            plan=new_plan,
            seats=seats,
            features=PLAN_FEATURES.get(new_plan, PLAN_FEATURES["developer"]),
            updated_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()
    logger.info(f"Licence updated for customer {customer_id}: plan={new_plan}, seats={seats}")


async def _handle_subscription_deleted(db: AsyncSession, subscription: dict) -> None:
    customer_id = subscription.get("customer")
    await db.execute(
        update(Licence)
        .where(Licence.stripe_customer_id == customer_id)
        .values(is_active=False, updated_at=datetime.now(timezone.utc))
    )
    await db.commit()
    logger.info(f"Licence deactivated for customer {customer_id}")


def _plan_from_stripe_items(subscription: dict) -> str:
    price_to_plan = {
        settings.stripe_price_developer_monthly: "developer",
        settings.stripe_price_developer_annual: "developer",
        settings.stripe_price_team_monthly: "team",
        settings.stripe_price_team_annual: "team",
    }
    for item in subscription.get("items", {}).get("data", []):
        price_id = item.get("price", {}).get("id")
        if price_id in price_to_plan:
            return price_to_plan[price_id]
    return ""
