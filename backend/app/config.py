from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str

    # API security
    secret_key: str
    admin_key: str

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_developer_monthly: str = ""
    stripe_price_developer_annual: str = ""
    stripe_price_team_monthly: str = ""
    stripe_price_team_annual: str = ""

    # Email
    sendgrid_api_key: str = ""
    from_email: str = "noreply@owlvex.io"

    # Runtime
    environment: str = "development"
    owlvex_pack_signing_private_key_pem: str = ""
    owlvex_pack_signing_key_id: str = ""
    billing_enabled: bool = False
    trust_forwarded_for: bool = False
    licence_validate_rate_limit: int = 20
    licence_register_rate_limit: int = 10
    prompt_build_rate_limit: int = 30
    pack_fetch_rate_limit: int = 60
    usage_event_rate_limit: int = 120
    rate_limit_window_seconds: int = 60
    email_verification_code_minutes: int = 15

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
