import pytest
from datetime import datetime, timezone
from app.models import AlertRule, CorrelatedAnomaly, Incident, LogEvent, MetricEvent


def test_redis_queue_enqueue_and_dequeue(test_queue, tenant_a):
    """
    Verify the Redis telemetry queue correctly enqueues and dequeues
    task envelopes with metadata and batch payloads.
    """
    batch_payload = {
        "logs": [
            {
                "timestamp": "2026-11-21T12:00:00Z",
                "service_name": "auth-service",
                "level": "INFO",
                "message": "Token generated successfully",
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T12:00:00Z",
                "service_name": "auth-service",
                "cpu_usage": 35.0,
                "latency": 45.0,
                "error_rate": 0.001,
            }
        ],
    }

    assert test_queue.length() == 0
    task_id = test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=batch_payload)
    assert task_id is not None
    assert test_queue.length() == 1

    dequeued_job = test_queue.dequeue(timeout=0)
    assert dequeued_job is not None
    assert dequeued_job["task_id"] == task_id
    assert dequeued_job["tenant_id"] == tenant_a["tenant"].id
    assert dequeued_job["batch"]["logs"][0]["service_name"] == "auth-service"
    assert dequeued_job["batch"]["metrics"][0]["cpu_usage"] == 35.0
    assert test_queue.length() == 0


def test_worker_processes_healthy_batch(test_worker, test_queue, tenant_a, db_session):
    """
    Verify that when healthy telemetry is enqueued, the worker:
    1. Persists logs and metrics under tenant_id.
    2. Flags zero anomalies.
    3. Creates zero incidents.
    """
    batch_payload = {
        "logs": [
            {
                "timestamp": "2026-11-21T12:10:00Z",
                "service_name": "billing-service",
                "level": "INFO",
                "message": "Invoice generated",
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T12:10:00Z",
                "service_name": "billing-service",
                "cpu_usage": 45.0,     # Below 85% threshold
                "latency": 120.0,      # Below 800ms threshold
                "error_rate": 0.005,   # 0.5% (below 5% threshold)
            }
        ],
    }

    test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=batch_payload)

    summary = test_worker.process_one(timeout=0)
    assert summary is not None
    assert summary["logs_ingested"] == 1
    assert summary["metrics_ingested"] == 1
    assert summary["anomalies_detected"] == 0
    assert summary["incidents_created"] == 0

    # Verify database persistence
    saved_log = db_session.query(LogEvent).filter(LogEvent.tenant_id == tenant_a["tenant"].id).first()
    assert saved_log is not None
    assert saved_log.service_name == "billing-service"

    saved_metric = db_session.query(MetricEvent).filter(MetricEvent.tenant_id == tenant_a["tenant"].id).first()
    assert saved_metric is not None
    assert saved_metric.cpu_usage == 45.0

    # Ensure no incidents or anomalies were created
    incidents = db_session.query(Incident).filter(Incident.tenant_id == tenant_a["tenant"].id).all()
    assert len(incidents) == 0


def test_worker_detects_anomalies_and_triggers_incident(test_worker, test_queue, tenant_a, db_session):
    """
    Verify that when metrics with CPU spikes and error rate jumps > 5% are processed:
    1. Anomaly detector flags both anomalies.
    2. Incident correlator creates an Incident in PostgreSQL with TRIGGERED status.
    3. Both anomalies are stored and linked to the incident.
    4. Recommended remediation plan is generated.
    """
    anomalous_batch = {
        "logs": [
            {
                "timestamp": "2026-11-21T12:15:00Z",
                "service_name": "order-service",
                "level": "ERROR",
                "message": "Database thread pool exhausted; request dropped",
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T12:15:00Z",
                "service_name": "order-service",
                "cpu_usage": 94.5,     # > 85% CPU Spike
                "latency": 1450.0,     # > 800ms Latency Spike
                "error_rate": 0.12,    # 12% Error rate (well above 5% threshold)
            }
        ],
    }

    test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=anomalous_batch)
    summary = test_worker.process_one(timeout=0)

    assert summary is not None
    assert summary["anomalies_detected"] == 3  # error_rate, cpu_usage, latency
    assert summary["incidents_created"] == 1

    # Query created Incident from database
    incident = db_session.query(Incident).filter(Incident.tenant_id == tenant_a["tenant"].id).first()
    assert incident is not None
    assert incident.service_name == "order-service"
    assert incident.status == "TRIGGERED"
    assert incident.severity in ["HIGH", "CRITICAL"]
    assert "remediation" in incident.remediation_plan.lower() or "scale" in incident.remediation_plan.lower()

    # Verify correlated anomalies linked to the incident
    anomalies = (
        db_session.query(CorrelatedAnomaly)
        .filter(CorrelatedAnomaly.incident_id == incident.id)
        .all()
    )
    assert len(anomalies) == 3
    metric_names = {a.metric_name for a in anomalies}
    assert "error_rate" in metric_names
    assert "cpu_usage" in metric_names
    assert "latency" in metric_names
    assert all(a.tenant_id == tenant_a["tenant"].id for a in anomalies)


def test_multi_service_cascade_correlation(test_worker, test_queue, tenant_a, db_session):
    """
    Verify that anomalies across multiple interrelated services
    (frontend-gateway and checkout-service) are grouped into a single unified incident.
    """
    multi_service_batch = {
        "metrics": [
            {
                "timestamp": "2026-11-21T12:20:00Z",
                "service_name": "frontend-gateway",
                "latency": 1200.0,      # Latency spike on gateway
            },
            {
                "timestamp": "2026-11-21T12:20:00Z",
                "service_name": "checkout-service",
                "error_rate": 0.09,     # 9% Error rate on downstream checkout
            },
        ]
    }

    test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=multi_service_batch)
    summary = test_worker.process_one(timeout=0)

    assert summary["anomalies_detected"] == 2
    assert summary["incidents_created"] == 1

    incident = db_session.query(Incident).filter(Incident.tenant_id == tenant_a["tenant"].id).first()
    assert incident is not None
    assert "multi-service" in incident.title.lower() or "degradation" in incident.title.lower()
    assert len(incident.anomalies) == 2
    services_in_anomalies = {a.service_name for a in incident.anomalies}
    assert services_in_anomalies == {"frontend-gateway", "checkout-service"}


def test_tenant_defined_alert_rule_evaluation(test_worker, test_queue, tenant_a, db_session):
    """
    Verify that custom tenant alert rules override or augment default thresholds.
    e.g., custom rule flags CPU usage > 70% (even though default is 85%).
    """
    custom_rule = AlertRule(
        tenant_id=tenant_a["tenant"].id,
        name="Strict CPU Alert for Ingest Worker",
        service_name="ingest-worker",
        metric_name="cpu_usage",
        threshold=70.0,
        comparison_operator=">",
        duration_seconds=60,
        severity="HIGH",
        is_enabled=True,
    )
    db_session.add(custom_rule)
    db_session.commit()

    batch = {
        "metrics": [
            {
                "timestamp": "2026-11-21T12:25:00Z",
                "service_name": "ingest-worker",
                "cpu_usage": 74.0,  # Below default 85%, but triggers tenant rule at 70%
            }
        ]
    }

    test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=batch)
    summary = test_worker.process_one(timeout=0)

    assert summary["anomalies_detected"] == 1
    assert summary["incidents_created"] == 1

    incident = db_session.query(Incident).filter(Incident.tenant_id == tenant_a["tenant"].id).first()
    assert incident is not None
    assert incident.service_name == "ingest-worker"


def test_async_ingest_endpoint_and_queue_drain(client, headers_a, test_worker, db_session, tenant_a):
    """
    Integration test:
    1. Client calls POST /api/v1/ingest?async_mode=true with anomalous payload.
    2. Endpoint immediately returns 202 with status="queued".
    3. Background worker drains queue.
    4. Client queries GET /api/v1/incidents and receives the newly detected incident.
    """
    payload = {
        "logs": [
            {
                "timestamp": "2026-11-21T12:30:00Z",
                "service_name": "payment-api",
                "level": "ERROR",
                "message": "Payment processor connection reset",
            }
        ],
        "metrics": [
            {
                "timestamp": "2026-11-21T12:30:00Z",
                "service_name": "payment-api",
                "error_rate": 0.18,  # 18% error rate
                "cpu_usage": 88.0,
            }
        ]
    }

    # Step 1: Call async ingest endpoint
    res_ingest = client.post("/api/v1/ingest?async_mode=true", headers=headers_a, json=payload)
    assert res_ingest.status_code == 202
    assert res_ingest.json()["status"] == "queued"

    # Step 2: Run worker to drain queue
    drained = test_worker.drain_all()
    assert drained == 1

    # Step 3: Query incidents via tenant API
    res_incidents = client.get("/api/v1/incidents", headers=headers_a)
    assert res_incidents.status_code == 200
    incidents = res_incidents.json()
    assert len(incidents) == 1
    assert incidents[0]["service_name"] == "payment-api"
    assert incidents[0]["status"] == "TRIGGERED"
    assert len(incidents[0]["anomalies"]) >= 1


def test_async_worker_cross_tenant_isolation(test_worker, test_queue, tenant_a, tenant_b, client, headers_a, headers_b):
    """
    Verify that background worker processing respects tenant isolation completely:
    - Tenant A's and Tenant B's anomalous batches are processed asynchronously.
    - Tenant A cannot see Tenant B's incident, and vice versa.
    """
    batch_a = {
        "metrics": [
            {
                "timestamp": "2026-11-21T12:35:00Z",
                "service_name": "acme-service",
                "error_rate": 0.20,
            }
        ]
    }
    batch_b = {
        "metrics": [
            {
                "timestamp": "2026-11-21T12:35:00Z",
                "service_name": "beta-service",
                "error_rate": 0.15,
            }
        ]
    }

    test_queue.enqueue(tenant_id=tenant_a["tenant"].id, batch=batch_a)
    test_queue.enqueue(tenant_id=tenant_b["tenant"].id, batch=batch_b)

    drained = test_worker.drain_all()
    assert drained == 2

    # Query Tenant A incidents
    res_a = client.get("/api/v1/incidents", headers=headers_a)
    assert res_a.status_code == 200
    inc_a = res_a.json()
    assert len(inc_a) == 1
    assert inc_a[0]["service_name"] == "acme-service"
    assert inc_a[0]["tenant_id"] == tenant_a["tenant"].id

    # Query Tenant B incidents
    res_b = client.get("/api/v1/incidents", headers=headers_b)
    assert res_b.status_code == 200
    inc_b = res_b.json()
    assert len(inc_b) == 1
    assert inc_b[0]["service_name"] == "beta-service"
    assert inc_b[0]["tenant_id"] == tenant_b["tenant"].id
