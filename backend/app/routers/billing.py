import logging
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Licence
from app.db.session import get_db
from app.routers.licences import PLAN_FEATURES
from app.services.email_service import send_licence_issued_email
from app.services.licence_service import generate_licence_key, hash_licence_key

router = APIRouter(prefix="/v1/billing", tags=["billing"])
logger = logging.getLogger(__name__)


def _redact_licence_key(raw_key: str) -> str:
    if len(raw_key) <= 8:
        return "redacted"
    return f"{raw_key[:4]}...{raw_key[-4:]}"


@router.post("/webhook/stripe")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    stripe_signature: str = Header(..., alias="Stripe-Signature"),
):
    settings = get_settings()
    if not settings.billing_enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Billing is disabled")

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, settings.stripe_webhook_secret)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature")
    except Exception as exc:
        logger.error("Stripe webhook error: %s", exc)
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
            logger.warning("Payment failed for customer %s - Stripe handling retries", data.get("customer"))
        else:
            logger.debug("Unhandled Stripe event: %s", event_type)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error processing Stripe event %s: %s", event_type, exc, exc_info=True)
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

    logger.info(
        "New licence created for %s (plan=%s). Key fingerprint: %s",
        customer_email,
        plan,
        _redact_licence_key(raw_key),
    )
    await _send_licence_email(customer_email, team_name, plan, raw_key)


async def _send_licence_email(email: str, team_name: str, plan: str, raw_key: str) -> None:
    settings = get_settings()
    if not settings.resend_api_key:
        logger.warning("Resend API key not configured; licence key not emailed")
        return

    try:
        send_licence_issued_email(
            to_email=email,
            team_name=team_name,
            plan=plan,
            raw_key=raw_key,
        )
        logger.info("Licence email sent to %s", email)
    except Exception as exc:
        logger.error("Failed to send licence email to %s: %s", email, exc)
        # Do not raise; licence is already created and email failure is non-fatal.


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
    logger.info("Licence updated for customer %s: plan=%s, seats=%s", customer_id, new_plan, seats)


async def _handle_subscription_deleted(db: AsyncSession, subscription: dict) -> None:
    customer_id = subscription.get("customer")
    await db.execute(
        update(Licence)
        .where(Licence.stripe_customer_id == customer_id)
        .values(is_active=False, updated_at=datetime.now(timezone.utc))
    )
    await db.commit()
    logger.info("Licence deactivated for customer %s", customer_id)


def _plan_from_stripe_items(subscription: dict) -> str:
    settings = get_settings()
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
