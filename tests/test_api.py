from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fedramp_viz.api import create_app
from fedramp_viz.providers import FileProvider

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "azure-sample.json"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("FEDRAMP_VIZ_TOKEN", raising=False)
    return TestClient(create_app(FileProvider(SAMPLE)))


def test_index_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "fedramp-viz" in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/docs").status_code == 404


def test_assessment_levels(client):
    for level in ("low", "moderate", "high"):
        r = client.get("/api/assessment", params={"level": level})
        assert r.status_code == 200
        assert r.json()["level"] == level
    assert client.get("/api/assessment", params={"level": "extreme"}).status_code == 400
    levels = client.get("/api/levels").json()
    assert set(levels) == {"low", "moderate", "high"}
    assert client.get("/api/meta").json()["resources"] == 32
    assert client.post("/api/rescan").json()["resources"] == 32


def test_token_required_when_configured(monkeypatch):
    monkeypatch.setenv("FEDRAMP_VIZ_TOKEN", "s3cret")
    c = TestClient(create_app(FileProvider(SAMPLE)))
    assert c.get("/").status_code == 200  # the shell is public, the data is not
    assert c.get("/api/meta").status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/meta", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/api/meta").json()["detail"] == "bearer token required"
