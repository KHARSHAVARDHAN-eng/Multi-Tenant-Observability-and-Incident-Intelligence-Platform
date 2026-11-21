import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models import AlertRule, CorrelatedAnomaly, MetricEvent


class AnomalyDetector:
    """
    Statistical and rule-based anomaly detection engine.
    Evaluates incoming telemetry metrics against tenant-defined alert thresholds
    and rolling-window statistical baselines (sudden latency spikes, error rate jumps > 5%, CPU spikes).
    """

    DEFAULT_ERROR_RATE_THRESHOLD = 0.05    # 5% error rate jump
    DEFAULT_CPU_THRESHOLD = 85.0           # 85% CPU utilization
    DEFAULT_LATENCY_THRESHOLD = 800.0      # 800ms latency spike
    Z_SCORE_THRESHOLD = 3.0                # 3-sigma statistical anomaly threshold

    def detect_anomalies(
        self,
        metrics: List[MetricEvent],
        tenant_id: str,
        db: Session,
    ) -> List[CorrelatedAnomaly]:
        """
        Evaluate metrics for a tenant, returning detected anomaly records.
        Strictly isolates rules and historical baselines by tenant_id.
        """
        if not metrics:
            return []

        # 1. Fetch active tenant alert rules
        tenant_rules = (
            db.query(AlertRule)
            .filter(AlertRule.tenant_id == tenant_id, AlertRule.is_enabled.is_(True))
            .all()
        )
        rule_map: Dict[tuple[str, str], AlertRule] = {
            (r.service_name, r.metric_name): r for r in tenant_rules
        }

        detected_anomalies: List[CorrelatedAnomaly] = []

        for metric in metrics:
            service = metric.service_name
            metric_ts = metric.timestamp or datetime.now(timezone.utc)

            # --- Check 1: Error Rate Anomalies (> 5% default or rule-based) ---
            if metric.error_rate is not None:
                rule = rule_map.get((service, "error_rate"))
                threshold = rule.threshold if rule else self.DEFAULT_ERROR_RATE_THRESHOLD
                operator = rule.comparison_operator if rule else ">="

                is_anomaly = self._evaluate_condition(metric.error_rate, operator, threshold)
                if is_anomaly:
                    score = min(1.0, 0.70 + (metric.error_rate * 2.5))
                    detected_anomalies.append(
                        CorrelatedAnomaly(
                            tenant_id=tenant_id,
                            service_name=service,
                            metric_name="error_rate",
                            anomaly_score=round(score, 3),
                            detected_at=metric_ts,
                            details={
                                "value": metric.error_rate,
                                "threshold": threshold,
                                "reason": f"Error rate {metric.error_rate:.1%} exceeded threshold {threshold:.1%}",
                                "rule_name": rule.name if rule else "default_error_rate_threshold",
                            },
                        )
                    )

            # --- Check 2: CPU Utilization Spikes (>= 85% default or rule-based) ---
            if metric.cpu_usage is not None:
                rule = rule_map.get((service, "cpu_usage"))
                threshold = rule.threshold if rule else self.DEFAULT_CPU_THRESHOLD
                operator = rule.comparison_operator if rule else ">="

                is_anomaly = self._evaluate_condition(metric.cpu_usage, operator, threshold)
                if is_anomaly:
                    score = min(1.0, 0.75 + (metric.cpu_usage - threshold) / 100.0)
                    detected_anomalies.append(
                        CorrelatedAnomaly(
                            tenant_id=tenant_id,
                            service_name=service,
                            metric_name="cpu_usage",
                            anomaly_score=round(score, 3),
                            detected_at=metric_ts,
                            details={
                                "value": metric.cpu_usage,
                                "threshold": threshold,
                                "reason": f"CPU usage {metric.cpu_usage:.1f}% exceeded threshold {threshold:.1f}%",
                                "rule_name": rule.name if rule else "default_cpu_threshold",
                            },
                        )
                    )

            # --- Check 3: Latency Spikes (>= 800ms default, rule-based, or rolling-window Z-score) ---
            if metric.latency is not None:
                rule = rule_map.get((service, "latency"))
                threshold = rule.threshold if rule else self.DEFAULT_LATENCY_THRESHOLD
                operator = rule.comparison_operator if rule else ">="

                is_anomaly = self._evaluate_condition(metric.latency, operator, threshold)

                z_score = self._compute_rolling_z_score(db, tenant_id, service, metric.latency)
                if z_score is not None and z_score >= self.Z_SCORE_THRESHOLD:
                    is_anomaly = True

                if is_anomaly:
                    score = min(1.0, 0.70 + (metric.latency - threshold) / 2000.0)
                    detected_anomalies.append(
                        CorrelatedAnomaly(
                            tenant_id=tenant_id,
                            service_name=service,
                            metric_name="latency",
                            anomaly_score=round(score, 3),
                            detected_at=metric_ts,
                            details={
                                "value": metric.latency,
                                "threshold": threshold,
                                "z_score": round(z_score, 2) if z_score else None,
                                "reason": f"Latency {metric.latency:.1f}ms spiked above threshold {threshold:.1f}ms"
                                + (f" (Z-score: {z_score:.2f})" if z_score else ""),
                                "rule_name": rule.name if rule else "default_latency_spike",
                            },
                        )
                    )

        return detected_anomalies

    @staticmethod
    def _evaluate_condition(value: float, operator: str, threshold: float) -> bool:
        if operator == ">":
            return value > threshold
        elif operator == ">=":
            return value >= threshold
        elif operator == "<":
            return value < threshold
        elif operator == "<=":
            return value <= threshold
        elif operator == "==":
            return math.isclose(value, threshold, rel_tol=1e-5)
        return False

    @staticmethod
    def _compute_rolling_z_score(
        db: Session,
        tenant_id: str,
        service_name: str,
        current_value: float,
        window_size: int = 20,
    ) -> Optional[float]:
        recent_metrics = (
            db.query(MetricEvent.latency)
            .filter(
                MetricEvent.tenant_id == tenant_id,
                MetricEvent.service_name == service_name,
                MetricEvent.latency.isnot(None),
            )
            .order_by(MetricEvent.timestamp.desc())
            .limit(window_size)
            .all()
        )

        values = [m[0] for m in recent_metrics if m[0] is not None]
        if len(values) < 5:
            return None

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)

        if std_dev < 1e-4:
            return None

        return (current_value - mean) / std_dev
