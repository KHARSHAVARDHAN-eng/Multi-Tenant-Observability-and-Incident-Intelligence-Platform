import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import LogEvent, MetricEvent
from app.queue import TelemetryQueue, telemetry_queue
from app.services.anomaly_detector import AnomalyDetector
from app.services.incident_correlator import IncidentCorrelator


class TelemetryWorker:
    """
    Background worker that consumes batches from Redis, decouples direct DB writes,
    persists logs and metrics under strict tenant isolation, and runs statistical
    anomaly detection and multi-service incident correlation.
    """

    def __init__(
        self,
        queue: TelemetryQueue = telemetry_queue,
        db_session_factory: Callable[[], Session] = SessionLocal,
        anomaly_detector: Optional[AnomalyDetector] = None,
        incident_correlator: Optional[IncidentCorrelator] = None,
    ):
        self.queue = queue
        self.db_session_factory = db_session_factory
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.incident_correlator = incident_correlator or IncidentCorrelator()

    def process_job_data(self, job_envelope: Dict[str, Any], db: Session) -> Dict[str, Any]:
        """
        Process a single job envelope containing tenant_id and telemetry batch.
        1. Persists logs and metrics into PostgreSQL under tenant_id.
        2. Evaluates metrics through AnomalyDetector.
        3. Groups anomalies and creates correlated Incidents via IncidentCorrelator.
        """
        task_id = job_envelope.get("task_id")
        tenant_id = job_envelope.get("tenant_id")
        batch = job_envelope.get("batch", {})

        logs_data = batch.get("logs", [])
        metrics_data = batch.get("metrics", [])

        # 1. Parse and persist LogEvents
        log_records = []
        for l in logs_data:
            ts = l.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            log_records.append(
                LogEvent(
                    tenant_id=tenant_id,
                    service_name=l["service_name"],
                    timestamp=ts or datetime.now(timezone.utc),
                    level=l.get("level", "INFO"),
                    message=l["message"],
                    attributes=l.get("attributes"),
                )
            )

        # 2. Parse and persist MetricEvents
        metric_records = []
        for m in metrics_data:
            ts = m.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            metric_records.append(
                MetricEvent(
                    tenant_id=tenant_id,
                    service_name=m["service_name"],
                    timestamp=ts or datetime.now(timezone.utc),
                    cpu_usage=m.get("cpu_usage"),
                    latency=m.get("latency"),
                    error_rate=m.get("error_rate"),
                    memory_usage=m.get("memory_usage"),
                    request_count=m.get("request_count"),
                    tags=m.get("tags"),
                )
            )

        if log_records:
            db.add_all(log_records)
        if metric_records:
            db.add_all(metric_records)

        db.flush()

        # 3. Detect anomalies on incoming metrics
        anomalies = self.anomaly_detector.detect_anomalies(metric_records, tenant_id, db)

        # 4. Correlate detected anomalies into incidents
        incidents = []
        if anomalies:
            incidents = self.incident_correlator.correlate_and_create_incidents(anomalies, tenant_id, db)

        db.commit()

        return {
            "task_id": task_id,
            "tenant_id": tenant_id,
            "logs_ingested": len(log_records),
            "metrics_ingested": len(metric_records),
            "anomalies_detected": len(anomalies),
            "incidents_created": len(incidents),
            "incident_ids": [str(inc.id) for inc in incidents],
        }

    def process_one(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """
        Pops and processes one task from the Redis queue.
        Returns the execution summary, or None if the queue was empty.
        """
        job = self.queue.dequeue(timeout=timeout)
        if not job:
            return None

        db = self.db_session_factory()
        try:
            return self.process_job_data(job, db)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def drain_all(self, max_tasks: int = 100) -> int:
        """
        Processes all available tasks in the queue until empty.
        Returns the number of tasks processed.
        """
        processed = 0
        while processed < max_tasks:
            result = self.process_one(timeout=0)
            if result is None:
                break
            processed += 1
        return processed

    async def run_worker_loop(self, stop_event: asyncio.Event, poll_interval: float = 0.1):
        """
        Continuous background worker loop for async task processing.
        """
        while not stop_event.is_set():
            result = self.process_one(timeout=1)
            if result is None:
                await asyncio.sleep(poll_interval)


if __name__ == "__main__":
    import signal
    import sys

    print("Starting Multi-Tenant Telemetry Background Worker...", flush=True)
    worker = TelemetryWorker()
    stop_event = asyncio.Event()

    def handle_sigterm(sig, frame):
        print("Received shutdown signal. Stopping worker...", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigterm)
    signal.signal(signal.SIGTERM, handle_sigterm)

    asyncio.run(worker.run_worker_loop(stop_event))
