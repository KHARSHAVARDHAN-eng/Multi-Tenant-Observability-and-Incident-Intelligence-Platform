from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


# ============================================================================
# Telemetry Ingestion Schemas
# ============================================================================

class LogIngestItem(BaseModel):
    timestamp: datetime = Field(..., description="UTC timestamp of the log event")
    service_name: str = Field(..., min_length=1, max_length=100, description="Service generating the log")
    level: str = Field(default="INFO", max_length=20, description="Log level: INFO, WARN, ERROR, DEBUG, etc.")
    message: str = Field(..., min_length=1, description="Raw log message or payload")
    attributes: Optional[Dict[str, Any]] = Field(default=None, description="Optional structured attributes/context")


class MetricIngestItem(BaseModel):
    timestamp: datetime = Field(..., description="UTC timestamp of the metric snapshot")
    service_name: str = Field(..., min_length=1, max_length=100, description="Service reporting the metrics")
    cpu_usage: Optional[float] = Field(
        default=None, ge=0.0, le=100.0, description="CPU utilization percentage (0.0 - 100.0)"
    )
    latency: Optional[float] = Field(
        default=None, ge=0.0, description="Response latency in milliseconds (>= 0.0)"
    )
    error_rate: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Fraction of requests failing (0.0 - 1.0)"
    )
    memory_usage: Optional[float] = Field(
        default=None, ge=0.0, le=100.0, description="Memory utilization percentage (0.0 - 100.0)"
    )
    request_count: Optional[int] = Field(
        default=None, ge=0, description="Total requests measured in interval"
    )
    tags: Optional[Dict[str, Any]] = Field(default=None, description="Metric tags / dimensions")

    @model_validator(mode="after")
    def validate_at_least_one_metric(self) -> "MetricIngestItem":
        metrics = [self.cpu_usage, self.latency, self.error_rate, self.memory_usage, self.request_count]
        if all(m is None for m in metrics):
            raise ValueError("At least one metric value (cpu_usage, latency, error_rate, memory_usage, request_count) must be provided.")
        return self


class BatchIngestRequest(BaseModel):
    logs: List[LogIngestItem] = Field(default_factory=list, description="List of log events to ingest")
    metrics: List[MetricIngestItem] = Field(default_factory=list, description="List of metric data points to ingest")

    @model_validator(mode="after")
    def validate_non_empty(self) -> "BatchIngestRequest":
        if not self.logs and not self.metrics:
            raise ValueError("Batch ingestion must contain at least one log event or metric data point.")
        return self


class BatchIngestResponse(BaseModel):
    status: str = "success"
    tenant_id: str
    logs_ingested: int
    metrics_ingested: int


# ============================================================================
# Alert Rule Schemas
# ============================================================================

class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    service_name: str = Field(..., min_length=1, max_length=100)
    metric_name: str = Field(..., min_length=1, max_length=100, description="Target metric, e.g., cpu_usage, latency, error_rate")
    threshold: float = Field(..., description="Numeric threshold value")
    comparison_operator: Literal[">", ">=", "<", "<=", "=="] = Field(..., description="Comparison operator")
    duration_seconds: int = Field(default=60, gt=0, description="Duration in seconds before triggering")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(default="HIGH")


class AlertRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    service_name: str
    metric_name: str
    threshold: float
    comparison_operator: str
    duration_seconds: int
    severity: str
    is_enabled: bool
    created_at: datetime


# ============================================================================
# AI Runbook Recommendation Schemas
# ============================================================================

class RunbookRecommendationResponse(BaseModel):
    incident_id: str
    summary: str
    suggested_fix: str
    confidence_score: float
    matched_runbook_title: str
    execution_steps: List[str]
    risks_and_impact: str
    generated_at: datetime


# ============================================================================
# Incident & Anomaly Schemas
# ============================================================================

class CorrelatedAnomalyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    incident_id: Optional[str]
    service_name: str
    metric_name: str
    anomaly_score: float
    detected_at: datetime
    details: Optional[Dict[str, Any]] = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    title: str
    description: Optional[str]
    service_name: str
    severity: str
    status: str
    remediation_plan: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    anomalies: List[CorrelatedAnomalyResponse] = Field(default_factory=list)


class IncidentDetailResponse(IncidentResponse):
    """
    Detailed incident payload including AI-generated RAG runbook recommendation.
    """
    runbook_recommendation: Optional[RunbookRecommendationResponse] = None


class IncidentApprovalRequest(BaseModel):
    approver: str = Field(..., min_length=1, max_length=100, description="User/SRE email or identifier performing the approval")
    decision: Literal["APPROVED", "REJECTED"] = Field(..., description="Approval decision: APPROVED or REJECTED")
    notes: Optional[str] = Field(default=None, max_length=1000, description="Optional justification or context for audit log")
    remediation_action_override: Optional[str] = Field(
        default=None, max_length=500, description="Optional customized remediation action to execute instead of default"
    )


class IncidentApprovalResponse(BaseModel):
    incident_id: str
    status: str
    decision: str
    approved_by: str
    audit_log_id: str
    message: str


# ============================================================================
# Audit Log Schemas
# ============================================================================

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    timestamp: datetime


# ============================================================================
# Tenant & API Key Schemas
# ============================================================================

class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100)
    tier: Optional[str] = Field(default="standard")


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    tier: str
    is_active: bool
    created_at: datetime


class APIKeyCreate(BaseModel):
    name: str = Field(default="Default API Key", max_length=100)


class APIKeyCreatedResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    prefix: str
    raw_api_key: str
    message: str = "Store this API key safely; it cannot be retrieved again."
