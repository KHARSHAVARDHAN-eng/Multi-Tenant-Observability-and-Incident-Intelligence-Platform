from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models import CorrelatedAnomaly, Incident


class IncidentCorrelator:
    """
    Intelligent incident correlation engine.
    Groups related telemetry anomalies across microservices occurring within a time window
    into unified incidents, assigns severity, recommends remediation plans,
    and automatically persists them to PostgreSQL.
    """

    def __init__(self, correlation_window_minutes: int = 15):
        self.correlation_window_minutes = correlation_window_minutes

    def correlate_and_create_incidents(
        self,
        anomalies: List[CorrelatedAnomaly],
        tenant_id: str,
        db: Session,
    ) -> List[Incident]:
        """
        Correlates a batch of detected anomalies into existing or new incidents for a tenant.
        Strictly confines correlation to tenant boundary.
        """
        if not anomalies:
            return []

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.correlation_window_minutes)

        # 1. Look for existing open incidents within correlation window
        open_incident = (
            db.query(Incident)
            .filter(
                Incident.tenant_id == tenant_id,
                Incident.status.in_(["TRIGGERED", "INVESTIGATING"]),
                Incident.created_at >= cutoff,
            )
            .order_by(Incident.created_at.desc())
            .first()
        )

        if open_incident:
            for anomaly in anomalies:
                anomaly.incident_id = open_incident.id
                db.add(anomaly)

            if any(a.anomaly_score >= 0.95 or (a.metric_name == "error_rate" and a.anomaly_score >= 0.85) for a in anomalies):
                open_incident.severity = "CRITICAL"

            open_incident.updated_at = now
            db.flush()
            return [open_incident]

        # 2. Group anomalies and create a new unified incident
        unique_services = sorted(list({a.service_name for a in anomalies}))
        unique_metrics = sorted(list({a.metric_name for a in anomalies}))

        if len(unique_services) > 1:
            primary_service = unique_services[0]
            title = f"Multi-Service Telemetry Degradation across {', '.join(unique_services)}"
            remediation = (
                f"Multi-service cascade detected across {', '.join(unique_services)}. "
                "Trigger circuit breaker, inspect shared database/network contention, and scale replicas."
            )
        else:
            primary_service = unique_services[0]
            metrics_label = " & ".join(m.replace("_", " ").title() for m in unique_metrics)
            title = f"{metrics_label} Spike on {primary_service}"

            if "error_rate" in unique_metrics and "cpu_usage" in unique_metrics:
                remediation = f"High CPU and failing requests on {primary_service}. Scale deployment replicas and review worker thread pools."
            elif "error_rate" in unique_metrics:
                remediation = f"Error rate spike on {primary_service}. Roll back recent deployment or redirect traffic to healthy replica pods."
            elif "cpu_usage" in unique_metrics:
                remediation = f"CPU utilization spike on {primary_service}. Scale replica count and investigate thread saturation."
            else:
                remediation = f"Latency spike on {primary_service}. Verify cache hit ratio and downstream service health."

        max_score = max(a.anomaly_score for a in anomalies)
        if max_score >= 0.95 or any(a.metric_name == "error_rate" and (a.details or {}).get("value", 0) >= 0.10 for a in anomalies):
            severity = "CRITICAL"
        elif max_score >= 0.80 or len(unique_services) > 1:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        description = (
            f"Automated intelligence correlated {len(anomalies)} anomalies across "
            f"services [{', '.join(unique_services)}] involving metrics [{', '.join(unique_metrics)}]."
        )

        incident = Incident(
            tenant_id=tenant_id,
            title=title,
            description=description,
            service_name=primary_service,
            severity=severity,
            status="TRIGGERED",
            remediation_plan=remediation,
            created_at=now,
            updated_at=now,
        )
        db.add(incident)
        db.flush()

        for anomaly in anomalies:
            anomaly.incident_id = incident.id
            db.add(anomaly)

        db.flush()
        return [incident]
