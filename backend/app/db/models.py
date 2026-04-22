import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, Float, ForeignKey, Integer, JSON, String, Text,
    TIMESTAMP, ARRAY, func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.session import Base


def _uuid():
    return str(uuid.uuid4())


class Framework(Base):
    __tablename__ = "frameworks"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code        = Column(String(50), nullable=False, unique=True)
    name        = Column(String(200), nullable=False)
    version     = Column(String(20), nullable=False)
    description = Column(Text)
    category    = Column(String(50))
    is_active   = Column(Boolean, default=True)
    plan_tier   = Column(String(20), default="developer")
    created_at  = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at  = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    rules            = relationship("Rule", back_populates="framework", cascade="all, delete")
    prompt_templates = relationship("PromptTemplate", back_populates="framework")


class Rule(Base):
    __tablename__ = "rules"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(UUID(as_uuid=True), ForeignKey("frameworks.id", ondelete="CASCADE"), nullable=False)
    code         = Column(String(50), nullable=False)
    title        = Column(String(200), nullable=False)
    description  = Column(Text, nullable=False)
    severity     = Column(String(20), nullable=False)
    languages    = Column(ARRAY(Text), default=list)
    cwe_id       = Column(String(20))
    prompt_hints = Column(Text)
    fix_guidance = Column(Text)
    rule_references = Column(JSONB, default=list)
    plan_tier    = Column(String(20), default="developer")
    is_active    = Column(Boolean, default=True)
    created_at   = Column(TIMESTAMP(timezone=True), server_default=func.now())

    framework = relationship("Framework", back_populates="rules")


class PromptTemplate(Base):
    __tablename__ = "prompt_templates"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id = Column(UUID(as_uuid=True), ForeignKey("frameworks.id", ondelete="SET NULL"), nullable=True)
    name         = Column(String(200), nullable=False)
    description  = Column(Text)
    language     = Column(String(50), default="all")
    template     = Column(Text, nullable=False)
    variables    = Column(JSONB, default=list)
    is_baseline  = Column(Boolean, default=False)
    is_active    = Column(Boolean, default=True)
    version      = Column(Integer, default=1)
    plan_tier    = Column(String(20), default="developer")
    created_at   = Column(TIMESTAMP(timezone=True), server_default=func.now())

    framework = relationship("Framework", back_populates="prompt_templates")


class Customer(Base):
    __tablename__ = "customers"

    id                           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email                        = Column(String(200), nullable=False, unique=True)
    name                         = Column(String(200))
    company                      = Column(String(200))
    source                       = Column(String(50), default="extension")
    pending_plan                 = Column(String(20))
    is_banned                    = Column(Boolean, default=False)
    banned_at                    = Column(TIMESTAMP(timezone=True))
    ban_reason                   = Column(Text)
    email_verified_at            = Column(TIMESTAMP(timezone=True))
    verification_code_hash       = Column(String(64))
    verification_code_expires_at = Column(TIMESTAMP(timezone=True))
    created_at                   = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at                   = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    licences    = relationship("Licence", back_populates="customer")
    notes       = relationship("CustomerNote", back_populates="customer", cascade="all, delete")
    audit_events = relationship("AdminAuditLog", back_populates="customer")


class CustomerIdentity(Base):
    __tablename__ = "customer_identities"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email             = Column(String(200), nullable=False, unique=True)
    trial_activated_at = Column(TIMESTAMP(timezone=True))
    free_activated_at  = Column(TIMESTAMP(timezone=True))
    created_at        = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at        = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())


class Licence(Base):
    __tablename__ = "licences"

    id                     = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id            = Column(UUID(as_uuid=True), ForeignKey("customers.id", ondelete="SET NULL"))
    licence_key_hash       = Column(String(64), nullable=False, unique=True)
    team_name              = Column(String(200), nullable=False)
    email                  = Column(String(200), nullable=False)
    plan                   = Column(String(20), nullable=False)
    seats                  = Column(Integer, default=1)
    seats_used             = Column(Integer, default=0)
    stripe_customer_id     = Column(String(100))
    stripe_subscription_id = Column(String(100))
    features               = Column(JSONB, default=dict)
    industry_packs         = Column(JSON().with_variant(JSONB, "postgresql"), default=list)
    is_active              = Column(Boolean, default=True)
    expires_at             = Column(TIMESTAMP(timezone=True))
    created_at             = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at             = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    customer    = relationship("Customer", back_populates="licences")
    seats_rel   = relationship("LicenceSeat", back_populates="licence", cascade="all, delete")
    scans       = relationship("ScanHistory", back_populates="licence")
    comparisons = relationship("Comparison", back_populates="licence")


class LicenceSeat(Base):
    __tablename__ = "licence_seats"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    licence_id = Column(UUID(as_uuid=True), ForeignKey("licences.id", ondelete="CASCADE"), nullable=False)
    user_email = Column(String(200), nullable=False)
    user_name  = Column(String(200))
    is_admin   = Column(Boolean, default=False)
    last_seen  = Column(TIMESTAMP(timezone=True))
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    licence = relationship("Licence", back_populates="seats_rel")


class TeamPrompt(Base):
    __tablename__ = "team_prompts"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    licence_id      = Column(UUID(as_uuid=True), ForeignKey("licences.id", ondelete="CASCADE"), nullable=False)
    name            = Column(String(200), nullable=False)
    description     = Column(Text)
    system_prompt   = Column(Text, nullable=False)
    frameworks      = Column(ARRAY(Text), default=list)
    model           = Column(String(100))
    temperature     = Column(Float, default=0.1)
    is_team_default = Column(Boolean, default=False)
    created_by      = Column(String(200))
    parent_id       = Column(UUID(as_uuid=True), ForeignKey("team_prompts.id"), nullable=True)
    created_at      = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at      = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    licence_id       = Column(UUID(as_uuid=True), ForeignKey("licences.id"), nullable=False)
    user_email       = Column(String(200))
    file_hash        = Column(String(64))
    file_name        = Column(String(500))
    language         = Column(String(50))
    prompt_id        = Column(UUID(as_uuid=True), ForeignKey("team_prompts.id"), nullable=True)
    model            = Column(String(100))
    provider         = Column(String(50))
    frameworks       = Column(ARRAY(Text), default=list)
    score            = Column(Float)
    finding_count    = Column(Integer, default=0)
    findings_summary = Column(JSONB, default=dict)
    token_count      = Column(Integer)
    duration_ms      = Column(Integer)
    status           = Column(String(20), default="completed")
    created_at       = Column(TIMESTAMP(timezone=True), server_default=func.now())

    licence     = relationship("Licence", back_populates="scans")
    comparisons_a = relationship("Comparison", foreign_keys="Comparison.scan_a_id")
    comparisons_b = relationship("Comparison", foreign_keys="Comparison.scan_b_id")


class Comparison(Base):
    __tablename__ = "comparisons"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    licence_id        = Column(UUID(as_uuid=True), ForeignKey("licences.id"), nullable=False)
    scan_a_id         = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=False)
    scan_b_id         = Column(UUID(as_uuid=True), ForeignKey("scan_history.id"), nullable=False)
    score_change      = Column(Float)
    new_findings      = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    diff_summary      = Column(JSONB, default=dict)
    created_at        = Column(TIMESTAMP(timezone=True), server_default=func.now())

    licence = relationship("Licence", back_populates="comparisons")
    scan_a  = relationship("ScanHistory", foreign_keys=[scan_a_id])
    scan_b  = relationship("ScanHistory", foreign_keys=[scan_b_id])


class UsageEvent(Base):
    __tablename__ = "usage_events"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    licence_id  = Column(UUID(as_uuid=True), ForeignKey("licences.id", ondelete="CASCADE"), nullable=False)
    user_email  = Column(String(200))
    event_name  = Column(String(80), nullable=False)
    event_data  = Column("metadata", JSONB, default=dict)
    created_at  = Column(TIMESTAMP(timezone=True), server_default=func.now())


class CustomerNote(Base):
    __tablename__ = "customer_notes"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id = Column(UUID(as_uuid=True), ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    author      = Column(String(200))
    note        = Column(Text, nullable=False)
    created_at  = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at  = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    customer    = relationship("Customer", back_populates="notes")


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    customer_id   = Column(UUID(as_uuid=True), ForeignKey("customers.id", ondelete="SET NULL"))
    licence_id    = Column(UUID(as_uuid=True), ForeignKey("licences.id", ondelete="SET NULL"))
    customer_email = Column(String(200))
    actor         = Column(String(200))
    action        = Column(String(100), nullable=False)
    reason        = Column(Text)
    environment   = Column(String(50))
    details       = Column(JSONB, default=dict)
    created_at    = Column(TIMESTAMP(timezone=True), server_default=func.now())

    customer      = relationship("Customer", back_populates="audit_events")
