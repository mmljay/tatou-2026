import pytest
from server import app


@pytest.mark.parametrize("endpoint", [
    "/api/create-user",
    "/api/login",
])
@pytest.mark.parametrize("invalid_body", [
    [],
    ["unexpected", "list"],
    12345,
    True,
    "unexpected string",
    None,
])
def test_api_rejects_non_object_json(endpoint, invalid_body):
    app.config["TESTING"] = False
    client = app.test_client()

    response = client.post(endpoint, json=invalid_body)

    assert response.status_code == 400, (
        f"{endpoint} received {invalid_body!r} "
        f"and returned HTTP {response.status_code}"
    )
