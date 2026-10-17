import pytest
from server import app


@pytest.mark.parametrize("invalid_email", [
    12345,
    True,
    ["test@example.com"],
    {"address": "test@example.com"},
])
def test_login_rejects_invalid_email_types(invalid_email):
    app.config["TESTING"] = False
    client = app.test_client()

    response = client.post("/api/login", json={
        "email": invalid_email,
        "password": "Test123!"
    })

    assert response.status_code == 400, (
        f"Expected HTTP 400 for {invalid_email!r}, "
        f"received HTTP {response.status_code}"
    )
