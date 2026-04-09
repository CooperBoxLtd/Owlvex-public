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

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
