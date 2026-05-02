import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from main import app
from database import init_db, DB_NAME
import os
import aiosqlite
import json

# Use a test database
TEST_DB = "test_network.db"

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    # Setup: override DB_NAME for tests
    import database
    original_db = database.DB_NAME
    database.DB_NAME = TEST_DB
    
    # Initialize test database
    await init_db()
    
    yield
    
    # Teardown: remove test database and restore original DB_NAME
    database.DB_NAME = original_db
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

@pytest.mark.asyncio
async def test_read_root():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_get_interfaces():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/interfaces")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert isinstance(response.json()["data"], list)

@pytest.mark.asyncio
async def test_get_history_empty():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/history")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total"] == 0
    assert data["data"] == []

@pytest.mark.asyncio
async def test_settings_flow():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Get default settings
        resp = await ac.get("/api/settings")
        assert resp.status_code == 200
        settings = resp.json()["data"]
        assert settings["scan_speed"] == "Normal"

        # Update settings
        new_settings = {"scan_speed": "Fast", "scan_interval": "10"}
        resp = await ac.post("/api/settings", json=new_settings)
        assert resp.status_code == 200
        assert resp.json()["data"]["scan_speed"] == "Fast"

        # Verify update
        resp = await ac.get("/api/settings")
        assert resp.json()["data"]["scan_speed"] == "Fast"
        assert resp.json()["data"]["scan_interval"] == "10"

@pytest.mark.asyncio
async def test_alerts_filtering():
    from database import save_alert
    # Inject some alerts
    await save_alert("Critical", "Test", "Critical Alert", "1.1.1.1")
    await save_alert("Low", "Test", "Low Alert", "2.2.2.2")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # All alerts
        resp = await ac.get("/api/alerts")
        assert resp.json()["total"] == 2

        # Filter by severity
        resp = await ac.get("/api/alerts?severity=Critical")
        assert resp.json()["total"] == 1
        assert resp.json()["data"][0]["severity"] == "Critical"

@pytest.mark.asyncio
async def test_history_pagination():
    from database import save_scan_results
    # Inject dummy scans
    dummy_results = [{"ip": f"192.168.1.{i}", "mac": "00:00:00", "vendor": "Test", "hostname": "Host", "risk_score": 0} for i in range(10)]
    await save_scan_results(dummy_results) # This creates 10 entries in scan_results

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/history?limit=5&page=1")
        assert resp.json()["total"] == 10
        assert len(resp.json()["data"]) == 5
        
        resp = await ac.get("/api/history?limit=5&page=2")
        assert len(resp.json()["data"]) == 5
