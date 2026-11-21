import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def hash_api_key(raw_key: str) -> str:
    """Generate SHA-256 hash of raw API key for secure storage."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key(prefix: str = "mp_live_") -> tuple[str, str, str]:
    """Generates (raw_key, key_hash, key_prefix)."""
    random_part = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{random_part}"
    key_hash = hash_api_key(raw_key)
    return raw_key, key_hash, prefix


class Tenant(Base):
    """
    Tenant entity representing an isolated customer/organization account.
    All observability data is partitioned strictly by tenant_id.
    """
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), unique=True, nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    tier = Column(String(50), default="standard", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    api_keys = relationship("APIKey", back_populates="tenant", cascade="all, delete-orphan")
    logs = relationship("LogEvent", back_populates="tenant", cascade="all, delete-orphan")
    metrics = relationship("MetricEvent", back_populates="tenant", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="tenant", cascade="all, delete-orphan")
    anomalies = relationship("CorrelatedAnomaly", back_populates="tenant", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="tenant", cascade="all, delete-orphan")
    alert_rules = relationship("AlertRule", back_populates="tenant", cascade="all, delete-orphan")


class APIKey(Base):
    """
    API Key entity for authenticating ingestion and tenant API requests.
    Only the SHA-256 hash of the API key is stored.
    """
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False, default="Default API Key")
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    prefix = Column(String(16), nullable=False, default="mp_live_")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_tenant_active", "tenant_id", "is_active"),
    )


class LogEvent(Base):
    """
    Ingested log event strictly partitioned by tenant_id.
    """
    __tablename__ = "log_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    service_name = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    level = Column(String(20), nullable=False, default="INFO")
    message = Column(Text, nullable=False)
    attributes = Column(JSON, nullable=True)

    tenant = relationship("Tenant", back_populates="logs")

    __table_args__ = (
        Index("ix_logs_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_logs_tenant_service", "tenant_id", "service_name"),
    )


class MetricEvent(Base):
    """
    Ingested metric event strictly partitioned by tenant_id.
    Tracks cpu_usage, latency, error_rate, and system metrics.
    """
    __tablename__ = "metric_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    service_name = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    cpu_usage = Column(Float, nullable=True)       # e.g., 78.5 (%)
    latency = Column(Float, nullable=True)         # e.g., 145.2 (ms)
    error_rate = Column(Float, nullable=True)      # e.g., 0.04 (4%)
    memory_usage = Column(Float, nullable=True)    # e.g., 62.1 (%)
    request_count = Column(Integer, nullable=True)
    tags = Column(JSON, nullable=True)

    tenant = relationship("Tenant", back_populates="metrics")

    __table_args__ = (
        Index("ix_metrics_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_metrics_tenant_service", "tenant_id", "service_name"),
    )


class Incident(Base):
    """
    Incident entity detected or created within a tenant boundary.
    Supports human-in-the-loop approvals for automated remediations.
    """
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    service_name = Column(String(100), nullable=False, index=True)
    severity = Column(String(50), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(50), nullable=False, default="TRIGGERED")  # TRIGGERED, INVESTIGATING, APPROVED, REJECTED, RESOLVED
    remediation_plan = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="incidents")
    anomalies = relationship("CorrelatedAnomaly", back_populates="incident", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_service", "tenant_id", "service_name"),
        Index("ix_incidents_tenant_created", "tenant_id", "created_at"),
    )


class CorrelatedAnomaly(Base):
    """
    Metric anomalies correlated with an incident or detected across tenant telemetry.
    """
    __tablename__ = "correlated_anomalies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    service_name = Column(String(100), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False)  # cpu_usage, latency, error_rate
    anomaly_score = Column(Float, nullable=False)      # e.g., 0.95
    detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    details = Column(JSON, nullable=True)

    tenant = relationship("Tenant", back_populates="anomalies")
    incident = relationship("Incident", back_populates="anomalies")

    __table_args__ = (
        Index("ix_anomalies_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_anomalies_tenant_service", "tenant_id", "service_name"),
    )


class AuditLog(Base):
    """
    Immutable audit log tracking all human and automated approvals/remediations.
    Strictly isolated per tenant.
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    actor = Column(String(100), nullable=False)           # e.g. "sre-lead@acme.com" or "service-worker"
    action = Column(String(100), nullable=False)          # e.g. "INCIDENT_APPROVED", "INCIDENT_REJECTED"
    resource_type = Column(String(100), nullable=False)   # e.g. "incident", "alert_rule"
    resource_id = Column(String(36), nullable=False)      # UUID of the affected entity
    details = Column(JSON, nullable=True)                 # metadata, rationale, action parameters
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    tenant = relationship("Tenant", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_audit_logs_tenant_resource", "tenant_id", "resource_type", "resource_id"),
    )


class AlertRule(Base):
    """
    Threshold and anomaly detection rules defined per tenant.
    """
    __tablename__ = "alert_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    service_name = Column(String(100), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False)  # cpu_usage, latency, error_rate
    threshold = Column(Float, nullable=False)
    comparison_operator = Column(String(10), nullable=False)  # >, >=, <, <=, ==
    duration_seconds = Column(Integer, default=60, nullable=False)
    severity = Column(String(50), default="HIGH", nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    tenant = relationship("Tenant", back_populates="alert_rules")

    __table_args__ = (
        Index("ix_alert_rules_tenant_service", "tenant_id", "service_name"),
    )

