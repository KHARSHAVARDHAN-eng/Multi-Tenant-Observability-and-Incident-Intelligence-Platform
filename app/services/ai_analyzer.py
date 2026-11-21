from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models import CorrelatedAnomaly, Incident


class RunbookRecommendation(BaseModel):
    """
    RAG-recommended runbook payload generated for an incident.
    """
    incident_id: str
    summary: str
    suggested_fix: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    matched_runbook_title: str
    execution_steps: List[str]
    risks_and_impact: str
    generated_at: datetime


class AIIncidentAnalyzer:
    """
    Simulated RAG-based AI runbook recommendation and root cause analyzer.
    Analyzes telemetry signals, anomalies, and service topologies to match
    against curated operational runbooks and synthesize contextualized remediation plans.
    """

    RUNBOOK_KNOWLEDGE_BASE = [
        {
            "id": "rb-cpu-saturation",
            "title": "Service CPU Saturation & Thread Pool Exhaustion Runbook (RB-101)",
            "keywords": ["cpu_usage", "cpu", "thread", "worker", "saturation", "spike"],
            "base_confidence": 0.94,
            "fix_template": "Scale {service} deployment replicas from baseline and check for runaway background threads.",
            "steps": [
                "1. Inspect active container CPU throttling metrics: `kubectl top pods -l app={service}`.",
                "2. Perform horizontal scaling: `kubectl scale deployment/{service} --replicas=+3`.",
                "3. Capture thread dump or profile CPU execution hotspots.",
                "4. If CPU remains pinned, enable rate-limiting on incoming edge gateway."
            ],
            "risks": "Horizontal pod autoscaling will increase load on downstream database connections."
        },
        {
            "id": "rb-error-rate-spike",
            "title": "Microservice High Error Rate & 5xx Cascade Runbook (RB-204)",
            "keywords": ["error_rate", "5xx", "timeout", "circuit_breaker", "gateway"],
            "base_confidence": 0.96,
            "fix_template": "Activate circuit breaker for {service} and roll back recent deployment canary.",
            "steps": [
                "1. Verify recent git deployments and Helm releases for {service} within the last 60 minutes.",
                "2. Trigger automated rollback: `kubectl rollout undo deployment/{service}`.",
                "3. Trip circuit breaker to prevent cascading failures to upstream dependencies.",
                "4. Check error log signatures for database connection resets or external API rate limits."
            ],
            "risks": "Tripping circuit breaker will return degraded fallback responses to end users."
        },
        {
            "id": "rb-latency-degradation",
            "title": "High P99 Latency & Cache Invalidation Runbook (RB-305)",
            "keywords": ["latency", "cache", "slow", "redis", "database", "delay"],
            "base_confidence": 0.91,
            "fix_template": "Flush and warm Redis cache partitions for {service} and scale database read replicas.",
            "steps": [
                "1. Check cache hit ratio on Redis cluster: `INFO stats` -> `keyspace_hits` vs `keyspace_misses`.",
                "2. Warm cache partitions for hot keys identified in telemetry.",
                "3. Verify slow query log on PostgreSQL database replica.",
                "4. Temporarily increase upstream HTTP request timeout from 3s to 8s during recovery."
            ],
            "risks": "Cache flushing may cause a momentary thundering herd on primary PostgreSQL database."
        },
        {
            "id": "rb-multi-service-cascade",
            "title": "Cross-Service Cascading Outage & Service Mesh Partition Runbook (RB-500)",
            "keywords": ["multi-service", "cascade", "degradation", "mesh", "network"],
            "base_confidence": 0.95,
            "fix_template": "Apply Istio fault isolation, restart ingress pods, and expand database connection pool size.",
            "steps": [
                "1. Isolate the blast radius by injecting Istio traffic-shedding rules.",
                "2. Restart healthy instances of the primary upstream gateway.",
                "3. Verify PostgreSQL active connections against `max_connections` ceiling.",
                "4. Drain and rebalance Kubernetes worker nodes experiencing network packet drops."
            ],
            "risks": "Traffic shedding will drop non-critical background traffic during incident stabilization."
        }
    ]

    def generate_recommendation(self, incident: Incident) -> RunbookRecommendation:
        """
        Analyze incident telemetry signals and anomalies to retrieve matching runbooks
        and synthesize actionable recommendations.
        """
        anomalies: List[CorrelatedAnomaly] = incident.anomalies or []
        metric_names = [a.metric_name.lower() for a in anomalies]
        service = incident.service_name or "target-service"
        title_lower = (incident.title or "").lower()

        # Score runbook matches based on keyword overlap
        best_match = None
        best_score = -1.0

        for rb in self.RUNBOOK_KNOWLEDGE_BASE:
            score = 0
            for kw in rb["keywords"]:
                if kw in metric_names:
                    score += 3
                if kw in title_lower:
                    score += 2

            if score > best_score:
                best_score = score
                best_match = rb

        # Fallback to general high error rate if low score
        if not best_match or best_score <= 0:
            best_match = self.RUNBOOK_KNOWLEDGE_BASE[1]

        # Calculate synthesized confidence score (bounded 0.82 - 0.98)
        confidence = min(0.98, max(0.82, best_match["base_confidence"] + (0.01 * min(len(anomalies), 4))))

        # Generate contextualized plain-language summary
        metrics_str = ", ".join(set(metric_names)) if metric_names else "anomalous telemetry"
        summary = (
            f"Incident '{incident.title}' on service '{service}' exhibits critical degradation across [{metrics_str}]. "
            f"RAG analysis matched operational runbook '{best_match['title']}'. "
            f"The primary root cause appears to be resource strain leading to latency and error propagation."
        )

        suggested_fix = best_match["fix_template"].format(service=service)
        formatted_steps = [step.format(service=service) for step in best_match["steps"]]

        return RunbookRecommendation(
            incident_id=str(incident.id),
            summary=summary,
            suggested_fix=suggested_fix,
            confidence_score=round(confidence, 2),
            matched_runbook_title=best_match["title"],
            execution_steps=formatted_steps,
            risks_and_impact=best_match["risks"],
            generated_at=datetime.now(timezone.utc),
        )


ai_incident_analyzer = AIIncidentAnalyzer()
