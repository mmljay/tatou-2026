from hypothesis import given, settings, strategies as st
from server import app

invalid_types = st.one_of(
    st.integers(),
    st.booleans(),
    st.none(),
    st.lists(st.text(max_size=20), max_size=5),
    st.dictionaries(
        st.text(max_size=10),
        st.text(max_size=20),
        max_size=3
    )
)

@given(
    field=st.sampled_from(["email", "password"]),
    invalid_value=invalid_types
)
@settings(max_examples=100, deadline=None)
def test_login_invalid_types_fuzz(field, invalid_value):
    app.config["TESTING"] = False
    client = app.test_client()

    payload = {
        "email": "fuzz@example.com",
        "password": "Test123!"
    }

    payload[field] = invalid_value

    response = client.post("/api/login", json=payload)

    assert response.status_code == 400, (
        f"Field {field} with value {invalid_value!r} "
        f"returned HTTP {response.status_code}"
    )
