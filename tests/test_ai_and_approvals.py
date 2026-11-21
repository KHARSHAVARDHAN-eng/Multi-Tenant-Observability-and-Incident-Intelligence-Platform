import pytest
from datetime import datetime, timezone
from app.models import AuditLog, CorrelatedAnomaly, Incident
from app.services.ai_analyzer import ai_incident_analyzer


def test_ai_runbook_recommendation_direct_generation(tenant_a, db_session):
    """
    Verify AIIncidentAnalyzer generates actionable, high-confidence runbooks
    based on incident telemetry anomalies.
    """
    incident = Incident(
        tenant_id=tenant_a["tenant_id"],
        title="High Error Rate in Payment Gateway",
        service_name="payment-gateway",
        severity="CRITICAL",
        status="TRIGGERED",
    )
    db_session.add(incident)
    db_session.flush()

    anomaly1 = CorrelatedAnomaly(
        tenant_id=tenant_a["tenant_id"],
        incident_id=incident.id,
        service_name="payment-gateway",
        metric_name="error_rate",
        anomaly_score=0.96,
        detected_at=datetime.now(timezone.utc),
        details={"value": 0.14, "reason": "5xx error rate spiked"},
    )
    anomaly2 = CorrelatedAnomaly(
        tenant_id=tenant_a["tenant_id"],
        incident_id=incident.id,
        service_name="payment-gateway",
        metric_name="latency",
        anomaly_score=0.90,
        detected_at=datetime.now(timezone.utc),
        details={"value": 1500.0, "reason": "Latency > 800ms"},
    )
    db_session.add_all([anomaly1, anomaly2])
    db_session.commit()
    db_session.refresh(incident)

    recommendation = ai_incident_analyzer.generate_recommendation(incident)
    assert recommendation is not None
    assert recommendation.incident_id == str(incident.id)
    assert 0.80 <= recommendation.confidence_score <= 1.0
    assert "payment-gateway" in recommendation.suggested_fix
    assert len(recommendation.execution_steps) >= 3
    assert "RB-" in recommendation.matched_runbook_title
    assert len(recommendation.summary) > 20


def test_get_incident_detail_with_runbook_endpoint(client, headers_a, tenant_a, db_session):
    """
    Verify GET /api/v1/incidents/{incident_id} returns incident details
    augmented with AI runbook recommendations.
    """
    incident = Incident(
        tenant_id=tenant_a["tenant_id"],
        title="CPU Saturation on Worker Pods",
        service_name="task-worker",
        severity="HIGH",
        status="TRIGGERED",
    )
    db_session.add(incident)
    db_session.flush()

    anomaly = CorrelatedAnomaly(
        tenant_id=tenant_a["tenant_id"],
        incident_id=incident.id,
        service_name="task-worker",
        metric_name="cpu_usage",
        anomaly_score=0.93,
        detected_at=datetime.now(timezone.utc),
        details={"value": 91.5},
    )
    db_session.add(anomaly)
    db_session.commit()

    # Query details endpoint
    res = client.get(f"/api/v1/incidents/{incident.id}", headers=headers_a)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == str(incident.id)
    assert data["service_name"] == "task-worker"
    assert data["runbook_recommendation"] is not None

    rb = data["runbook_recommendation"]
    assert "task-worker" in rb["suggested_fix"]
    assert rb["confidence_score"] > 0.85
    assert len(rb["execution_steps"]) > 0

    # Query dedicated runbook endpoint
    res_rb = client.get(f"/api/v1/incidents/{incident.id}/runbook", headers=headers_a)
    assert res_rb.status_code == 200
    assert res_rb.json()["matched_runbook_title"] == rb["matched_runbook_title"]


def test_ai_runbook_cross_tenant_isolation(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    SECURITY TEST:
    Tenant A must NOT be able to view details or runbook recommendations
    for an incident belonging to Tenant B.
    Platform must return 404 Not Found.
    """
    incident_b = Incident(
        tenant_id=tenant_b["tenant_id"],
        title="Beta Confidential Database Lockup",
        service_name="beta-db",
        severity="CRITICAL",
        status="TRIGGERED",
    )
    db_session.add(incident_b)
    db_session.commit()

    # Tenant A attempts to access Tenant B's incident details
    res_detail = client.get(f"/api/v1/incidents/{incident_b.id}", headers=headers_a)
    assert res_detail.status_code == 404
    assert res_detail.json()["detail"] == "Incident not found"

    # Tenant A attempts to access Tenant B's runbook
    res_rb = client.get(f"/api/v1/incidents/{incident_b.id}/runbook", headers=headers_a)
    assert res_rb.status_code == 404
    assert res_rb.json()["detail"] == "Incident not found"


def test_incident_approval_and_rejection_audit_logging(client, headers_a, tenant_a, db_session):
    """
    Verify full Human-in-the-Loop workflow:
    1. SRE approves remediation with notes and overrides.
    2. Audit log is emitted with full context.
    3. Another incident is rejected by operator, status updated and audited.
    """
    # 1. Approval case
    incident_1 = Incident(
        tenant_id=tenant_a["tenant_id"],
        title="Cache Stampede on Catalog API",
        service_name="catalog-api",
        severity="HIGH",
        status="TRIGGERED",
        remediation_plan="Flush Redis cluster and scale deployment",
    )
    db_session.add(incident_1)

    # 2. Rejection case
    incident_2 = Incident(
        tenant_id=tenant_a["tenant_id"],
        title="Spurious Network Blip",
        service_name="edge-proxy",
        severity="MEDIUM",
        status="TRIGGERED",
        remediation_plan="Restart edge proxy",
    )
    db_session.add(incident_2)
    db_session.commit()

    # Approve incident_1
    approval_payload = {
        "approver": "lead-sre@acme.com",
        "decision": "APPROVED",
        "notes": "Verified telemetry; approving replica increase.",
        "remediation_action_override": "Scale to 8 replicas instead of 5",
    }
    res_app = client.post(
        f"/api/v1/incidents/{incident_1.id}/approve",
        headers=headers_a,
        json=approval_payload,
    )
    assert res_app.status_code == 200
    app_data = res_app.json()
    assert app_data["status"] == "APPROVED"
    assert app_data["approved_by"] == "lead-sre@acme.com"

    # Verify audit log in DB
    audit_1 = db_session.query(AuditLog).filter(AuditLog.id == app_data["audit_log_id"]).first()
    assert audit_1 is not None
    assert audit_1.tenant_id == tenant_a["tenant_id"]
    assert audit_1.action == "INCIDENT_REMEDIATION_APPROVED"
    assert audit_1.details["remediation_action_override"] == "Scale to 8 replicas instead of 5"

    # Reject incident_2
    rejection_payload = {
        "approver": "oncall-eng@acme.com",
        "decision": "REJECTED",
        "notes": "Identified as routine maintenance; auto-remediation cancelled.",
    }
    res_rej = client.post(
        f"/api/v1/incidents/{incident_2.id}/approve",
        headers=headers_a,
        json=rejection_payload,
    )
    assert res_rej.status_code == 200
    rej_data = res_rej.json()
    assert rej_data["status"] == "REJECTED"

    # Verify state in DB
    db_session.refresh(incident_2)
    assert incident_2.status == "REJECTED"

    audit_2 = db_session.query(AuditLog).filter(AuditLog.id == rej_data["audit_log_id"]).first()
    assert audit_2 is not None
    assert audit_2.action == "INCIDENT_REMEDIATION_REJECTED"


def test_cross_tenant_approval_and_audit_boundary(client, headers_a, headers_b, tenant_a, tenant_b, db_session):
    """
    CRITICAL SECURITY CHECK:
    Tenant A attempting to approve Tenant B's incident must be rejected with 404,
    and must not leak any audit log entry into Tenant B's log stream.
    """
    incident_b = Incident(
        tenant_id=tenant_b["tenant_id"],
        title="Beta Production Kafka Partition Stalled",
        service_name="kafka-cluster",
        severity="CRITICAL",
        status="TRIGGERED",
    )
    db_session.add(incident_b)
    db_session.commit()

    malicious_payload = {
        "approver": "rogue@tenant-a.com",
        "decision": "APPROVED",
        "notes": "Attempting cross-tenant tampering",
    }
    res = client.post(
        f"/api/v1/incidents/{incident_b.id}/approve",
        headers=headers_a,
        json=malicious_payload,
    )
    assert res.status_code == 404
    assert res.json()["detail"] == "Incident not found"

    # Verify Tenant B's incident state is unchanged
    db_session.refresh(incident_b)
    assert incident_b.status == "TRIGGERED"

    # Verify Tenant B's audit logs are completely untouched
    audit_logs_b = db_session.query(AuditLog).filter(AuditLog.tenant_id == tenant_b["tenant_id"]).all()
    assert len(audit_logs_b) == 0
