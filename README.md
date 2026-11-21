# Multi-Tenant Observability and Incident Intelligence Platform

[![CI / Pytest](https://img.shields.io/badge/pytest-18%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)]()
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791.svg)]()
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)]()
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)]()
[![Kubernetes](https://img.shields.io/badge/k8s-manifests-326CE5.svg)]()

A production-grade, multi-tenant cloud observability and incident intelligence platform built with **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.0**, **PostgreSQL**, and **Redis**.

The platform is designed to ingest high-throughput telemetry (logs and metrics), execute statistical and rule-based anomaly detection, automatically correlate multi-service cascades into unified incidents, generate AI-driven runbook remediation recommendations, and enforce human-in-the-loop approvals backed by an immutable audit trail—all under **strict multi-tenant isolation guarantees**.

---

## Key Architecture Capabilities

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Tenant Ingestion API                   │
                  │   POST /api/v1/ingest (X-API-Key SHA-256 Auth)        │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      │                                               │
             [Sync Fallback]                                [Async High-Throughput]
                      │                                               │
                      ▼                                               ▼
              Direct DB Writes                                  Redis Queue
                      │                           (observability:telemetry:ingest)
                      │                                               │
                      │                                               ▼
                      │                                    TelemetryWorker
                      │                         (Batch Dequeue & DB Persistence)
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              │
                                              ▼
                                   AnomalyDetector Engine
                 (Error Rate > 5% | CPU >= 85% | Latency >= 800ms | 3-Sigma Z-Score)
                                              │
                                              ▼
                                 IncidentCorrelator Engine
             (Sliding Time Window | Cross-Service Cascades | Severity & Remediation Plan)
                                              │
                                              ▼
                                 PostgreSQL Relational DB
                       (Strict Tenant Isolation via tenant_id FKs & Indexes)
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
             AIIncidentAnalyzer                            Human-in-the-Loop SRE
         (RAG Runbook Synthesis)                      POST /api/v1/incidents/{id}/approve
                      │                                               │
                      ▼                                               ▼
        Executable Remediation Plan                        Immutable Audit Log
       & Diagnostic Confidence Score                  (Actor, Action, Overrides, IP)
```

1. **Strict Multi-Tenant Isolation**:
   - Every database table (`log_events`, `metric_events`, `incidents`, `correlated_anomalies`, `alert_rules`, `audit_logs`, `api_keys`) enforces a non-nullable `tenant_id` foreign key with `ON DELETE CASCADE`.
   - Optimized composite indexes `(tenant_id, timestamp)`, `(tenant_id, service_name)`, and `(tenant_id, status)` ensure zero cross-tenant index scans.
   - Authentication via `X-API-Key` using SHA-256 hashing.
   - Anti-enumeration protection: querying or modifying resources belonging to another tenant returns `404 Not Found` rather than `403 Forbidden`.

2. **Decoupled Asynchronous Telemetry Ingestion**:
   - `POST /api/v1/ingest?async_mode=true` pushes batch envelopes to an in-memory or Redis FIFO queue (`TelemetryQueue`), returning an immediate `202 Accepted` (`status="queued"`).
   - `TelemetryWorker` runs in the background, consuming telemetry batches, bulk-inserting logs and metrics, and executing the intelligence pipeline.

3. **Statistical Anomaly Detection & Incident Correlation**:
   - **Default Heuristics**: Detects error rate jumps $>5\%$, CPU utilization spikes $\ge 85\%$, and latency spikes $\ge 800\text{ ms}$.
   - **Tenant-Defined Rules**: Dynamically loads custom tenant `AlertRule` thresholds and comparison operators (`>`, `>=`, `<`, `<=`, `==`).
   - **Rolling Window Z-Score**: Evaluates moving mean ($\mu$) and standard deviation ($\sigma$) to flag 3-sigma statistical outliers ($Z \ge 3.0$).
   - **Multi-Service Cascades**: Automatically groups related anomalies across services within sliding correlation windows into single unified `Incident` records with assigned severity (`CRITICAL`, `HIGH`, `MEDIUM`).

4. **AI Runbook Recommendation Engine**:
   - `AIIncidentAnalyzer` simulates RAG-based runbook retrieval against operational knowledge bases (CPU saturation, error rate spikes, latency degradation, and service mesh partitions).
   - Generates plain-language root-cause summaries, confidence scores ($0.80 - 1.0$), tailored suggested fixes, step-by-step diagnostic procedures, and risk evaluations.

5. **Human-in-the-Loop Approvals & Immutable Audit Logs**:
   - Operators review incidents and AI runbooks, approving or rejecting automated actions via `POST /api/v1/incidents/{id}/approve`.
   - Emits immutable `AuditLog` entries recording operator identity, decision, custom remediation overrides, client IP, and UTC timestamps.

---

## Project Structure

```
├── app/
│   ├── __init__.py
│   ├── database.py                   # SQLAlchemy engine, SessionLocal, Base, get_db
│   ├── models.py                     # ORM models with composite tenant indexes
│   ├── schemas.py                    # Pydantic v2 schemas with strict validators
│   ├── queue.py                      # Redis connection pool & TelemetryQueue
│   ├── worker.py                     # TelemetryWorker background batch runner
│   ├── services/
│   │   ├── __init__.py
│   │   ├── anomaly_detector.py       # Statistical and rule-based anomaly detector
│   │   ├── incident_correlator.py    # Multi-service anomaly grouping and incident creator
│   │   └── ai_analyzer.py            # RAG-based AI runbook recommendation engine
│   └── main.py                       # FastAPI application & authenticated endpoints
├── database.py                       # Top-level re-export for modular imports
├── models.py                         # Top-level re-export
├── schemas.py                        # Top-level re-export
├── k8s/
│   ├── configmap.yml                 # Kubernetes ConfigMap for platform configuration
│   ├── deployment.yml                # Kubernetes Deployments for API and background Worker
│   └── service.yml                   # Kubernetes Service (ClusterIP routing to port 8000)
├── tests/
│   ├── __init__.py
│   ├── conftest.py                   # Pytest fixtures (DB sessions, fake_redis, test workers)
│   ├── test_isolation.py             # Tenant data isolation and authentication tests
│   ├── test_workers.py               # Redis queue, async ingestion, and anomaly tests
│   └── test_ai_and_approvals.py      # AI runbook synthesis and human approval audit tests
├── Dockerfile                        # Multi-stage production container build (non-root)
├── docker-compose.yml                # Full stack: PostgreSQL 15, Redis 7, API, Worker
├── requirements.txt                  # Production and development dependencies
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/ingest` | Batch telemetry ingestion (supports `?async_mode=true`) |
| `GET` | `/api/v1/incidents` | List incidents strictly scoped to authenticated tenant |
| `GET` | `/api/v1/incidents/{id}` | Retrieve incident details with AI runbook recommendation |
| `GET` | `/api/v1/incidents/{id}/runbook` | Generate/retrieve AI runbook recommendation |
| `POST` | `/api/v1/incidents/{id}/approve` | Approve/reject incident remediation with audit logging |
| `POST` | `/api/v1/alert-rules` | Create tenant-specific anomaly detection threshold rule |
| `GET` | `/api/v1/alert-rules` | List tenant alert rules |
| `GET` | `/api/v1/audit-logs` | Retrieve tenant audit trail (filtered by resource) |
| `POST` | `/api/v1/tenants` | Onboard a new tenant organization |
| `POST` | `/api/v1/tenants/{id}/api-keys` | Generate a new API key for a tenant |
| `GET` | `/health` | Service health check |

---

## Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+
- PostgreSQL 15+ (or SQLite for local test runs)
- Redis 7+

### 2. Installation
```bash
git clone https://github.com/KHARSHAVARDHAN-eng/Multi-Tenant-Observability-and-Incident-Intelligence-Platform.git
cd Multi-Tenant-Observability-and-Incident-Intelligence-Platform

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run Locally
```bash
# Start the FastAPI Web Server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Start the Asynchronous Background Worker (in a separate terminal)
python -m app.worker
```

---

## Running with Docker Compose

Deploy the complete multi-service stack with a single command:

```bash
docker-compose up --build
```

This spins up:
- **`observability_postgres`**: PostgreSQL 15 with automated healthchecks and persistent volume.
- **`observability_redis`**: Redis 7 cache and ingestion queue.
- **`observability_api`**: FastAPI server on port 8000.
- **`observability_worker`**: Background telemetry ingestion and anomaly correlation worker.

Verify service health:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"multi-tenant-observability-platform"}
```

---

## Kubernetes Deployment

Deploy to any Kubernetes cluster (Minikube, EKS, GKE, AKS):

```bash
# 1. Apply platform configuration
kubectl apply -f k8s/configmap.yml

# 2. Deploy API and background worker pods
kubectl apply -f k8s/deployment.yml

# 3. Expose the API service
kubectl apply -f k8s/service.yml

# 4. Check deployment status
kubectl get pods -l app=observability-api
kubectl get pods -l app=observability-worker
```

---

## Running the Test Suite

The test suite thoroughly verifies multi-tenant isolation, anti-enumeration security, Redis queue decoupling, statistical anomaly detection, AI runbook generation, and human approval audit logging:

```bash
pytest -v
```

### Test Output:
```
tests/test_ai_and_approvals.py::test_ai_runbook_recommendation_direct_generation PASSED [  5%]
tests/test_ai_and_approvals.py::test_get_incident_detail_with_runbook_endpoint PASSED [ 11%]
tests/test_ai_and_approvals.py::test_ai_runbook_cross_tenant_isolation PASSED [ 16%]
tests/test_ai_and_approvals.py::test_incident_approval_and_rejection_audit_logging PASSED [ 22%]
tests/test_ai_and_approvals.py::test_cross_tenant_approval_and_audit_boundary PASSED [ 27%]
tests/test_isolation.py::test_authentication_enforcement PASSED          [ 33%]
tests/test_isolation.py::test_telemetry_batch_ingest_isolation PASSED    [ 38%]
tests/test_isolation.py::test_incidents_query_isolation PASSED           [ 44%]
tests/test_isolation.py::test_cross_tenant_approval_denial PASSED        [ 50%]
tests/test_isolation.py::test_successful_approval_and_audit_log_isolation PASSED [ 55%]
tests/test_isolation.py::test_validation_constraints PASSED              [ 61%]
tests/test_workers.py::test_redis_queue_enqueue_and_dequeue PASSED       [ 66%]
tests/test_workers.py::test_worker_processes_healthy_batch PASSED        [ 72%]
tests/test_workers.py::test_worker_detects_anomalies_and_triggers_incident PASSED [ 77%]
tests/test_workers.py::test_multi_service_cascade_correlation PASSED     [ 83%]
tests/test_workers.py::test_tenant_defined_alert_rule_evaluation PASSED  [ 88%]
tests/test_workers.py::test_async_ingest_endpoint_and_queue_drain PASSED [ 94%]
tests/test_workers.py::test_async_worker_cross_tenant_isolation PASSED   [100%]

======================== 18 passed in 0.19s =========================
```

---

## License

MIT License. Designed and engineered for high-performance cloud observability and incident automation.
