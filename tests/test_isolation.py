from datetime import datetime, timezone
import pytest
from app.models import AuditLog, CorrelatedAnomaly, Incident, LogEvent, MetricEvent


def test_authentication_enforcement(client):
    """
    Ensure API key authentication is strictly enforced.
    - Missing header returns 401
    - Invalid key returns 401
    """
    res_no_key = client.get("/api/v1/incidents")
    assert res_no_key.status_code == 401
    assert "Missing required authentication header" in res_no_key.json()["detail"]

    res_bad_key = client.get("/api/v1/incidents", headers={"X-API-Key": "invalid_bogus_key"})
    assert res_bad_key.status_code == 401
    assert "Invalid or expired API Key" in res_bad_key.json()["detail"]


def test_telemetry_batch_ingest_isolation(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    Ensure batched logs and metrics ingested by Tenant A and Tenant B
    are strictly tagged and partitioned by their respective tenant_id.
    """
    payload_a = {
        "logs": [
            {
                "timestamp": "2026-11-21T10:00:00Z",
                "service_name": "checkout-service",
                "level": "ERROR",
                "message": "Payment gateway timeout for order #1001",
                "attributes": {"order_id": 1001, "customer": "tenant_a_user"}
            },
            {
                "timestamp": "2026-11-21T10:00:05Z",
                "service_name": "cart-service",
                "level": "INFO",
                "message": "Item added to cart",
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T10:00:00Z",
                "service_name": "checkout-service",
                "cpu_usage": 85.5,
                "latency": 320.4,
                "error_rate": 0.08,
            },
            {
                "timestamp": "2026-11-21T10:00:10Z",
                "service_name": "checkout-service",
                "cpu_usage": 91.0,
                "latency": 450.0,
                "error_rate": 0.12,
            }
        ]
    }
    res_a = client.post("/api/v1/ingest", headers=headers_a, json=payload_a)
    assert res_a.status_code == 202
    data_a = res_a.json()
    assert data_a["status"] == "success"
    assert data_a["tenant_id"] == tenant_a["tenant"].id
    assert data_a["logs_ingested"] == 2
    assert data_a["metrics_ingested"] == 2

    payload_b = {
        "logs": [
            {
                "timestamp": "2026-11-21T10:05:00Z",
                "service_name": "fleet-tracking",
                "level": "WARN",
                "message": "GPS signal degradation on vehicle #99",
                "attributes": {"vehicle_id": 99}
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T10:05:00Z",
                "service_name": "fleet-tracking",
                "cpu_usage": 42.0,
                "latency": 55.2,
                "error_rate": 0.01,
            }
        ]
    }
    res_b = client.post("/api/v1/ingest", headers=headers_b, json=payload_b)
    assert res_b.status_code == 202
    data_b = res_b.json()
    assert data_b["status"] == "success"
    assert data_b["tenant_id"] == tenant_b["tenant"].id
    assert data_b["logs_ingested"] == 1
    assert data_b["metrics_ingested"] == 1

    logs_for_a = db_session.query(LogEvent).filter(LogEvent.tenant_id == tenant_a["tenant"].id).all()
    assert len(logs_for_a) == 2
    assert all(log.tenant_id == tenant_a["tenant"].id for log in logs_for_a)

    metrics_for_a = db_session.query(MetricEvent).filter(MetricEvent.tenant_id == tenant_a["tenant"].id).all()
    assert len(metrics_for_a) == 2
    assert all(m.tenant_id == tenant_a["tenant"].id for m in metrics_for_a)

    logs_for_b = db_session.query(LogEvent).filter(LogEvent.tenant_id == tenant_b["tenant"].id).all()
    assert len(logs_for_b) == 1
    assert logs_for_b[0].service_name == "fleet-tracking"

    metrics_for_b = db_session.query(MetricEvent).filter(MetricEvent.tenant_id == tenant_b["tenant"].id).all()
    assert len(metrics_for_b) == 1
    assert metrics_for_b[0].service_name == "fleet-tracking"


def test_incidents_query_isolation(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    Ensure Tenant A can NEVER see Tenant B's incidents when querying GET /api/v1/incidents.
    """
    incident_a = Incident(
        tenant_id=tenant_a["tenant"].id,
        title="High Error Rate in Checkout Service",
        description="Checkout error rate exceeded 5% threshold",
        service_name="checkout-service",
        severity="CRITICAL",
        status="TRIGGERED",
        remediation_plan="Restart pod deployment and scale replicas to 5",
    )
    db_session.add(incident_a)
    db_session.flush()

    anomaly_a = CorrelatedAnomaly(
        tenant_id=tenant_a["tenant"].id,
        incident_id=incident_a.id,
        service_name="checkout-service",
        metric_name="error_rate",
        anomaly_score=0.98,
        detected_at=datetime.now(timezone.utc),
        details={"spiked_at": "10:00:00Z", "peak_rate": 0.12},
    )
    db_session.add(anomaly_a)

    incident_b = Incident(
        tenant_id=tenant_b["tenant"].id,
        title="GPS Gateway Latency Spike",
        description="P99 latency exceeding 5000ms",
        service_name="fleet-tracking",
        severity="HIGH",
        status="INVESTIGATING",
        remediation_plan="Flush Redis cache and restart worker nodes",
    )
    db_session.add(incident_b)
    db_session.commit()

    res_a = client.get("/api/v1/incidents", headers=headers_a)
    assert res_a.status_code == 200
    incidents_a = res_a.json()
    assert len(incidents_a) == 1
    assert incidents_a[0]["id"] == str(incident_a.id)
    assert incidents_a[0]["title"] == "High Error Rate in Checkout Service"
    assert incidents_a[0]["tenant_id"] == tenant_a["tenant"].id
    assert len(incidents_a[0]["anomalies"]) == 1
    assert incidents_a[0]["anomalies"][0]["anomaly_score"] == 0.98

    res_b = client.get("/api/v1/incidents", headers=headers_b)
    assert res_b.status_code == 200
    incidents_b = res_b.json()
    assert len(incidents_b) == 1
    assert incidents_b[0]["id"] == str(incident_b.id)
    assert incidents_b[0]["title"] == "GPS Gateway Latency Spike"
    assert incidents_b[0]["tenant_id"] == tenant_b["tenant"].id

    a_ids = [inc["id"] for inc in incidents_a]
    assert str(incident_b.id) not in a_ids

    b_ids = [inc["id"] for inc in incidents_b]
    assert str(incident_a.id) not in b_ids


def test_cross_tenant_approval_denial(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    CRITICAL SECURITY CHECK:
    Tenant A must NOT be able to approve, reject, or alter Tenant B's incident.
    The platform must return 404 Not Found to prevent ID enumeration.
    """
    incident_b = Incident(
        tenant_id=tenant_b["tenant"].id,
        title="Beta Production Database Pressure",
        service_name="db-cluster",
        severity="CRITICAL",
        status="TRIGGERED",
        remediation_plan="Failover to replica db-02",
    )
    db_session.add(incident_b)
    db_session.commit()

    approval_payload = {
        "approver": "malicious_operator@tenant-a.com",
        "decision": "APPROVED",
        "notes": "Attempting unauthorized cross-tenant approval",
    }
    res = client.post(
        f"/api/v1/incidents/{incident_b.id}/approve",
        headers=headers_a,
        json=approval_payload,
    )

    assert res.status_code == 404
    assert res.json()["detail"] == "Incident not found"

    db_session.refresh(incident_b)
    assert incident_b.status == "TRIGGERED"

    audit_logs_b = db_session.query(AuditLog).filter(AuditLog.tenant_id == tenant_b["tenant"].id).all()
    assert len(audit_logs_b) == 0


def test_successful_approval_and_audit_log_isolation(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    Ensure that:
    1. Tenant A can approve its own incident.
    2. Status is updated to APPROVED.
    3. An AuditLog entry is generated strictly under Tenant A.
    4. Tenant B querying audit logs receives ZERO records from Tenant A.
    """
    incident_a = Incident(
        tenant_id=tenant_a["tenant"].id,
        title="Payment Service Memory Leak",
        service_name="payment-svc",
        severity="HIGH",
        status="TRIGGERED",
        remediation_plan="Rolling restart of payment-svc pods",
    )
    db_session.add(incident_a)
    db_session.commit()

    payload = {
        "approver": "sre-lead@acme.com",
        "decision": "APPROVED",
        "notes": "Confirmed memory leak from telemetry. Approved rolling restart.",
        "remediation_action_override": "Rolling restart with max_unavailable=1",
    }
    res_approve = client.post(
        f"/api/v1/incidents/{incident_a.id}/approve",
        headers=headers_a,
        json=payload,
    )
    assert res_approve.status_code == 200
    approval_data = res_approve.json()
    assert approval_data["status"] == "APPROVED"
    assert approval_data["decision"] == "APPROVED"
    assert approval_data["approved_by"] == "sre-lead@acme.com"
    audit_id = approval_data["audit_log_id"]

    db_session.refresh(incident_a)
    assert incident_a.status == "APPROVED"

    audit_record = db_session.query(AuditLog).filter(AuditLog.id == audit_id).first()
    assert audit_record is not None
    assert audit_record.tenant_id == tenant_a["tenant"].id
    assert audit_record.actor == "sre-lead@acme.com"
    assert audit_record.action == "INCIDENT_REMEDIATION_APPROVED"
    assert audit_record.resource_id == str(incident_a.id)

    res_b_audit = client.get("/api/v1/audit-logs", headers=headers_b)
    assert res_b_audit.status_code == 200
    assert len(res_b_audit.json()) == 0

    res_a_audit = client.get("/api/v1/audit-logs", headers=headers_a)
    assert res_a_audit.status_code == 200
    tenant_a_logs = res_a_audit.json()
    assert len(tenant_a_logs) == 1
    assert tenant_a_logs[0]["id"] == audit_id
    assert tenant_a_logs[0]["tenant_id"] == tenant_a["tenant"].id


def test_validation_constraints(client, headers_a):
    """
    Test Pydantic v2 validation constraints:
    - Empty batch is rejected
    - Negative latency is rejected
    - CPU > 100 is rejected
    - Error rate > 1.0 is rejected
    """
    empty_payload = {"logs": [], "metrics": []}
    res_empty = client.post("/api/v1/ingest", headers=headers_a, json=empty_payload)
    assert res_empty.status_code == 422

    invalid_cpu = {
        "metrics": [
            {
                "timestamp": "2026-11-21T10:00:00Z",
                "service_name": "worker",
                "cpu_usage": 150.0,
            }
        ]
    }
    res_cpu = client.post("/api/v1/ingest", headers=headers_a, json=invalid_cpu)
    assert res_cpu.status_code == 422

    negative_latency = {
        "metrics": [
            {
                "timestamp": "2026-11-21T10:00:00Z",
                "service_name": "worker",
                "latency": -10.0,
            }
        ]
    }
    res_lat = client.post("/api/v1/ingest", headers=headers_a, json=negative_latency)
    assert res_lat.status_code == 422

    invalid_error_rate = {
        "metrics": [
            {
                "timestamp": "2026-11-21T10:00:00Z",
                "service_name": "worker",
                "error_rate": 2.5,
            }
        ]
    }
    res_err = client.post("/api/v1/ingest", headers=headers_a, json=invalid_error_rate)
    assert res_err.status_code == 422
