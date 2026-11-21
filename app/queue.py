import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
QUEUE_KEY = os.getenv("TELEMETRY_QUEUE_KEY", "observability:telemetry:ingest")


class TelemetryQueue:
    """
    Redis-backed queue for asynchronous telemetry batch ingestion.
    Decouples HTTP ingestion endpoints from database persistence and anomaly detection.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None, queue_key: str = QUEUE_KEY):
        self.queue_key = queue_key
        if redis_client is not None:
            self.redis = redis_client
        else:
            try:
                self.pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
                self.redis = redis.Redis(connection_pool=self.pool)
                self.redis.ping()
            except Exception:
                try:
                    import fakeredis
                    self.redis = fakeredis.FakeRedis(decode_responses=True)
                except ImportError:
                    raise

    def enqueue(self, tenant_id: str, batch: Dict[str, Any]) -> str:
        """
        Push serialized telemetry batch payload to the Redis queue.
        Returns the unique task/job ID.
        """
        task_id = str(uuid.uuid4())
        job_envelope = {
            "task_id": task_id,
            "tenant_id": tenant_id,
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
            "batch": batch,
        }
        serialized = json.dumps(job_envelope)
        self.redis.rpush(self.queue_key, serialized)
        return task_id

    def dequeue(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """
        Pops the next telemetry batch from Redis (FIFO).
        - If timeout <= 0, performs a non-blocking lpop.
        - If timeout > 0, performs a blocking blpop up to timeout seconds.
        Returns the job envelope dictionary, or None if the queue is empty.
        """
        if timeout <= 0:
            raw_data = self.redis.lpop(self.queue_key)
            if not raw_data:
                return None
        else:
            result = self.redis.blpop(self.queue_key, timeout=timeout)
            if not result:
                return None
            _, raw_data = result

        try:
            return json.loads(raw_data)
        except Exception:
            return None

    def length(self) -> int:
        """Get the current length of the ingestion queue."""
        return self.redis.llen(self.queue_key)

    def clear(self) -> None:
        """Clear all tasks in the ingestion queue."""
        self.redis.delete(self.queue_key)


# Global default queue instance
telemetry_queue = TelemetryQueue()
