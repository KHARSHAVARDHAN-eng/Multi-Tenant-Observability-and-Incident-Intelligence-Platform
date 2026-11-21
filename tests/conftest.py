import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import APIKey, Tenant, generate_api_key
from app.queue import TelemetryQueue
from app.services.anomaly_detector import AnomalyDetector
from app.services.incident_correlator import IncidentCorrelator
from app.worker import TelemetryWorker

# In-memory SQLite with StaticPool for fast, isolated testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all database schema tables once per test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Provides a database session per test function and cleans up table rows after test."""
    session = TestingSessionLocal()
    yield session
    session.close()

    # Clean tables after test to ensure 100% isolation between test runs
    with test_engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.commit()


@pytest.fixture
def fake_redis():
    """Provides a fresh in-memory fakeredis client for queue testing."""
    client = fakeredis.FakeRedis(decode_responses=True)
    client.flushall()
    return client


@pytest.fixture
def test_queue(fake_redis):
    """Provides an isolated TelemetryQueue instance backed by fake_redis."""
    return TelemetryQueue(redis_client=fake_redis, queue_key="test:telemetry:ingest")


@pytest.fixture
def test_worker(test_queue):
    """Provides a TelemetryWorker wired to test_queue and TestingSessionLocal."""
    return TelemetryWorker(
        queue=test_queue,
        db_session_factory=TestingSessionLocal,
        anomaly_detector=AnomalyDetector(),
        incident_correlator=IncidentCorrelator(),
    )


@pytest.fixture
def client(db_session, test_queue):
    """FastAPI TestClient with overridden get_db dependency and test queue."""
    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    import app.main as main_module
    old_telemetry_queue = main_module.telemetry_queue
    main_module.telemetry_queue = test_queue

    with TestClient(app) as test_client:
        yield test_client

    main_module.telemetry_queue = old_telemetry_queue
    app.dependency_overrides.clear()


@pytest.fixture
def tenant_a(db_session):
    """Create Tenant A (Acme Corp)."""
    tenant = Tenant(
        name="Acme Corporation",
        slug="acme-corp",
        tier="enterprise",
        is_active=True,
    )
    db_session.add(tenant)
    db_session.flush()

    raw_key, key_hash, prefix = generate_api_key("ak_acme_")
    api_key = APIKey(
        tenant_id=tenant.id,
        name="Acme Ingestion Key",
        key_hash=key_hash,
        prefix=prefix,
        is_active=True,
    )
    db_session.add(api_key)
    db_session.commit()

    return {"tenant": tenant, "tenant_id": str(tenant.id), "raw_key": raw_key, "api_key": api_key}


@pytest.fixture
def tenant_b(db_session):
    """Create Tenant B (Beta Corp)."""
    tenant = Tenant(
        name="Beta Logistics",
        slug="beta-logistics",
        tier="standard",
        is_active=True,
    )
    db_session.add(tenant)
    db_session.flush()

    raw_key, key_hash, prefix = generate_api_key("ak_beta_")
    api_key = APIKey(
        tenant_id=tenant.id,
        name="Beta Ingestion Key",
        key_hash=key_hash,
        prefix=prefix,
        is_active=True,
    )
    db_session.add(api_key)
    db_session.commit()

    return {"tenant": tenant, "tenant_id": str(tenant.id), "raw_key": raw_key, "api_key": api_key}


@pytest.fixture
def headers_a(tenant_a):
    return {"X-API-Key": tenant_a["raw_key"]}


@pytest.fixture
def headers_b(tenant_b):
    return {"X-API-Key": tenant_b["raw_key"]}
