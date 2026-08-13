import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_login_wrong_credentials(client):
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": "nobody@test.com", "password": "wrong"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_protected_without_token(client):
    r = await client.get("/api/v1/alerts")
    assert r.status_code == 401
