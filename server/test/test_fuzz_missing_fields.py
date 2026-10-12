import pytest
from server import app


@pytest.mark.parametrize("endpoint,payload", [
    ("/api/create-user", {}),
    ("/api/create-user", {"email": "test@example.com"}),
    ("/api/create-user", {
        "email": "",
        "login": "testuser",
        "password": "Test123!"
    }),
    ("/api/create-user", {
        "email": "test@example.com",
        "login": "",
        "password": "Test123!"
    }),
    ("/api/create-user", {
        "email": "test@example.com",
        "login": "testuser",
        "password": ""
    }),
    ("/api/login", {}),
    ("/api/login", {"email": "test@example.com"}),
    ("/api/login", {"password": "Test123!"}),
    ("/api/login", {
        "email": "",
        "password": "Test123!"
    }),
    ("/api/login", {
        "email": "test@example.com",
        "password": ""
    }),
])
def test_required_fields_validation(endpoint, payload):
    app.config["TESTING"] = False
    client = app.test_client()

    response = client.post(endpoint, json=payload)

    assert response.status_code == 400, (
        f"{endpoint} with {payload!r} "
        f"returned HTTP {response.status_code}"
    )
