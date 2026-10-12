from hypothesis import given, settings, strategies as st
from server import app

# Generate invalid email types
invalid_emails = st.one_of(
    st.integers(),
    st.booleans(),
    st.lists(st.text(max_size=20), max_size=5),
    st.dictionaries(
        st.text(max_size=10),
        st.text(max_size=20),
        max_size=3
    )
)

@given(invalid_email=invalid_emails)
@settings(max_examples=100, deadline=None)
def test_create_user_invalid_email_fuzz(invalid_email):
    app.config["TESTING"] = False
    client = app.test_client()

    response = client.post("/api/create-user", json={
        "email": invalid_email,
        "login": "fuzz_test_user",
        "password": "Test123!"
    })

    assert response.status_code == 400, (
        f"Input {invalid_email!r} returned "
        f"HTTP {response.status_code}"
    )


@given(
    field=st.sampled_from(["login", "password"]),
    invalid_value=invalid_emails
)
@settings(max_examples=100, deadline=None)
def test_create_user_other_fields_fuzz(field, invalid_value):
    app.config["TESTING"] = False
    client = app.test_client()

    payload = {
        "email": "fuzz@example.com",
        "login": "fuzz_test_user",
        "password": "Test123!"
    }

    payload[field] = invalid_value

    response = client.post("/api/create-user", json=payload)

    assert response.status_code == 400, (
        f"Field {field} with value {invalid_value!r} "
        f"returned HTTP {response.status_code}"
    )
