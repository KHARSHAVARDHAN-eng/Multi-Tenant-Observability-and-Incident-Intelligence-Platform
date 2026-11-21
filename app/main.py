from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Security, status
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import (
    APIKey,
    AlertRule,
    AuditLog,
    CorrelatedAnomaly,
    Incident,
    LogEvent,
    MetricEvent,
    Tenant,
    generate_api_key,
    hash_api_key,
)
from app.queue import telemetry_queue
from app.schemas import (
    AlertRuleCreate,
    AlertRuleResponse,
    AuditLogResponse,
    BatchIngestRequest,
    BatchIngestResponse,
    IncidentApprovalRequest,
    IncidentApprovalResponse,
    IncidentDetailResponse,
    IncidentResponse,
    RunbookRecommendationResponse,
    TenantCreate,
    TenantResponse,
    APIKeyCreate,
    APIKeyCreatedResponse,
)
from app.services.ai_analyzer import ai_incident_analyzer

# Initialize database schemas
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Multi-Tenant Observability and Incident Intelligence Platform",
    description="High-throughput telemetry ingestion, incident correlation, AI runbook recommendations, and human-in-the-loop approvals with strict tenant isolation.",
    version="1.0.0",
)

# Header scheme for API Key
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ============================================================================
# Tenant Authentication Dependency
# ============================================================================

def get_current_tenant(
    x_api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db),
) -> Tenant:
    """
    Authenticate and resolve the calling tenant via X-API-Key header.
    Strictly verifies API key hash and tenant active status.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication header: X-API-Key",
        )

    # Hash the provided raw key with SHA-256
    hashed_key = hash_api_key(x_api_key)

    # Query active API key
    api_key_record = (
        db.query(APIKey)
        .filter(APIKey.key_hash == hashed_key, APIKey.is_active.is_(True))
        .first()
    )

    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API Key",
        )

    # Check key expiration if set
    if api_key_record.expires_at and api_key_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key has expired",
        )

    # Fetch corresponding tenant
    tenant = db.query(Tenant).filter(Tenant.id == api_key_record.tenant_id, Tenant.is_active.is_(True)).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant account is disabled or does not exist",
        )

    return tenant


# ============================================================================
# Core API Endpoints
# ============================================================================

@app.post(
    "/api/v1/ingest",
    response_model=BatchIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Batch Ingest Telemetry (Logs & Metrics)",
)
def ingest_telemetry(
    payload: BatchIngestRequest,
    async_mode: bool = Query(False, description="Decouple direct DB writes and push to Redis telemetry queue"),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """
    Accept batched log events and metric snapshots.
    - If async_mode is True: enqueues to Redis queue for background worker processing.
    - If async_mode is False: synchronously writes to database.
    Injects current tenant_id into each record for strict isolation.
    """
    if async_mode:
        telemetry_queue.enqueue(tenant_id=current_tenant.id, batch=payload.model_dump(mode="json"))
        return BatchIngestResponse(
            status="queued",
            tenant_id=str(current_tenant.id),
            logs_ingested=len(payload.logs),
            metrics_ingested=len(payload.metrics),
        )

    log_records = [
        LogEvent(
            tenant_id=current_tenant.id,
            service_name=item.service_name,
            timestamp=item.timestamp,
            level=item.level,
            message=item.message,
            attributes=item.attributes,
        )
        for item in payload.logs
    ]

    metric_records = [
        MetricEvent(
            tenant_id=current_tenant.id,
            service_name=item.service_name,
            timestamp=item.timestamp,
            cpu_usage=item.cpu_usage,
            latency=item.latency,
            error_rate=item.error_rate,
            memory_usage=item.memory_usage,
            request_count=item.request_count,
            tags=item.tags,
        )
        for item in payload.metrics
    ]

    if log_records:
        db.add_all(log_records)
    if metric_records:
        db.add_all(metric_records)

    db.commit()

    return BatchIngestResponse(
        status="success",
        tenant_id=str(current_tenant.id),
        logs_ingested=len(log_records),
        metrics_ingested=len(metric_records),
    )


@app.get(
    "/api/v1/incidents",
    response_model=List[IncidentResponse],
    summary="Query Tenant Incidents",
)
def get_incidents(
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by incident status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """
    Retrieve incidents strictly scoped to the authenticated tenant.
    Cross-tenant querying is strictly prevented by enforcing tenant_id filtering.
    """
    query = db.query(Incident).filter(Incident.tenant_id == current_tenant.id)

    if service_name:
        query = query.filter(Incident.service_name == service_name)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity:
        query = query.filter(Incident.severity == severity)

    incidents = (
        query.order_by(Incident.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return incidents


@app.get(
    "/api/v1/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get Incident Details with AI Runbook Recommendation",
)
def get_incident_detail(
    incident_id: str,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """
    Retrieve incident details and AI-recommended runbook suggestions.
    Strictly scoped to current tenant. Returns 404 across tenant boundaries.
    """
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.tenant_id == current_tenant.id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    runbook = ai_incident_analyzer.generate_recommendation(incident)
    return {
        "id": str(incident.id),
        "tenant_id": str(incident.tenant_id),
        "title": incident.title,
        "description": incident.description,
        "service_name": incident.service_name,
        "severity": incident.severity,
        "status": incident.status,
        "remediation_plan": incident.remediation_plan,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "resolved_at": incident.resolved_at,
        "anomalies": incident.anomalies,
        "runbook_recommendation": runbook,
    }


@app.get(
    "/api/v1/incidents/{incident_id}/runbook",
    response_model=RunbookRecommendationResponse,
    summary="Generate AI Runbook Recommendation for Incident",
)
def get_incident_runbook(
    incident_id: str,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """
    Generate or retrieve RAG-based AI runbook recommendation for an incident.
    Strictly scoped to current tenant.
    """
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.tenant_id == current_tenant.id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return ai_incident_analyzer.generate_recommendation(incident)


@app.post(
    "/api/v1/incidents/{incident_id}/approve",
    response_model=IncidentApprovalResponse,
    summary="Human-in-the-Loop Incident Remediation Approval",
)
def approve_incident_remediation(
    incident_id: str,
    payload: IncidentApprovalRequest,
    request: Request,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """
    Approve or reject automated remediation for an incident.
    - Strictly checks that incident belongs to the caller's tenant_id (returns 404 otherwise).
    - Updates incident status.
    - Emits an immutable audit log record for regulatory/compliance tracking.
    """
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.tenant_id == current_tenant.id)
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    if incident.status == "RESOLVED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident is already resolved and cannot be modified",
        )

    prev_status = incident.status
    new_status = "APPROVED" if payload.decision == "APPROVED" else "REJECTED"
    incident.status = new_status
    incident.updated_at = datetime.now(timezone.utc)

    client_ip = request.client.host if request.client else None

    audit_entry = AuditLog(
        tenant_id=current_tenant.id,
        actor=payload.approver,
        action=f"INCIDENT_REMEDIATION_{payload.decision}",
        resource_type="incident",
        resource_id=str(incident.id),
        details={
            "decision": payload.decision,
            "previous_status": prev_status,
            "new_status": new_status,
            "notes": payload.notes,
            "remediation_action_override": payload.remediation_action_override,
            "remediation_plan": incident.remediation_plan,
        },
        ip_address=client_ip,
        timestamp=datetime.now(timezone.utc),
    )

    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)

    return IncidentApprovalResponse(
        incident_id=str(incident.id),
        status=new_status,
        decision=payload.decision,
        approved_by=payload.approver,
        audit_log_id=str(audit_entry.id),
        message=f"Incident remediation {payload.decision.lower()} successfully recorded.",
    )


# ============================================================================
# Additional Tenant Scoped Endpoints (Alert Rules, Audit Logs, Onboarding)
# ============================================================================

@app.post(
    "/api/v1/alert-rules",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Tenant Alert Rule",
)
def create_alert_rule(
    payload: AlertRuleCreate,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Create an alert rule scoped to current tenant."""
    rule = AlertRule(
        tenant_id=current_tenant.id,
        name=payload.name,
        service_name=payload.service_name,
        metric_name=payload.metric_name,
        threshold=payload.threshold,
        comparison_operator=payload.comparison_operator,
        duration_seconds=payload.duration_seconds,
        severity=payload.severity,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@app.get(
    "/api/v1/alert-rules",
    response_model=List[AlertRuleResponse],
    summary="Query Tenant Alert Rules",
)
def get_alert_rules(
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """List alert rules strictly scoped to current tenant."""
    return db.query(AlertRule).filter(AlertRule.tenant_id == current_tenant.id).all()


@app.get(
    "/api/v1/audit-logs",
    response_model=List[AuditLogResponse],
    summary="Query Tenant Audit Logs",
)
def get_audit_logs(
    resource_type: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Retrieve audit logs strictly scoped to the authenticated tenant."""
    query = db.query(AuditLog).filter(AuditLog.tenant_id == current_tenant.id)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)

    return (
        query.order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@app.post(
    "/api/v1/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Tenant (Admin/Onboarding)",
)
def create_tenant(
    payload: TenantCreate,
    db: Session = Depends(get_db),
):
    """Onboard a new tenant organization."""
    existing = db.query(Tenant).filter((Tenant.name == payload.name) | (Tenant.slug == payload.slug)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A tenant with this name or slug already exists",
        )

    tenant = Tenant(
        name=payload.name,
        slug=payload.slug,
        tier=payload.tier or "standard",
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@app.post(
    "/api/v1/tenants/{tenant_id}/api-keys",
    response_model=APIKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate API Key for Tenant",
)
def create_tenant_api_key(
    tenant_id: str,
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
):
    """Generate and return an API key for a tenant."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    raw_key, key_hash, prefix = generate_api_key()
    api_key_record = APIKey(
        tenant_id=tenant.id,
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
    )
    db.add(api_key_record)
    db.commit()
    db.refresh(api_key_record)

    return APIKeyCreatedResponse(
        id=str(api_key_record.id),
        tenant_id=str(tenant.id),
        name=api_key_record.name,
        prefix=prefix,
        raw_api_key=raw_key,
    )


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "multi-tenant-observability-platform"}
