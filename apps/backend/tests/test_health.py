from fastapi.testclient import TestClient

from app.core.errors import NotFoundError
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_health_returns_exact_contract():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "application": "PCAP-MAN"}


def test_response_has_request_id_header():
    response = client.get("/health")
    assert response.headers["x-request-id"]


def test_unknown_route_uses_standard_error_format():
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "http_error"
    assert error["request_id"]


def test_app_error_uses_standard_error_format():
    @app.get("/_test/not-found")
    def _raise_not_found():
        raise NotFoundError("Capture not found.")

    response = client.get("/_test/not-found")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_unexpected_error_hides_details():
    @app.get("/_test/boom")
    def _boom():
        raise RuntimeError("secret internal detail")

    response = client.get("/_test/boom")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "secret" not in response.text
