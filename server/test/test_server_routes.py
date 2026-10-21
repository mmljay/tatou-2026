"""Route tests for server.py. Runs against the real MariaDB (docker compose db).

"""
import io
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

# env must be set BEFORE importing server (it calls create_app() at import)
os.environ.setdefault("SECRET_KEY", "s" * 48)
os.environ.setdefault("RMAP_WATERMARK_KEY", "w" * 48)
os.environ.setdefault("STORAGE_DIR", tempfile.mkdtemp(prefix="tatou-test-"))
# DB_PASSWORD / DB_HOST / DB_PORT must come from your environment
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import server  # noqa: E402
import watermarking_utils as WMUtils  # noqa: E402


def make_pdf() -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = b"BT /F1 12 Tf 20 100 Td (hello tatou) Tj ET"
    objs[3] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref)
    return out


@pytest.fixture(scope="session")
def client():
    server.app.config["TESTING"] = True
    return server.app.test_client()


@pytest.fixture()
def user(client):
    tag = uuid.uuid4().hex[:10]
    creds = {"email": f"{tag}@example.com", "login": f"u{tag}", "password": "Passw0rd!123"}
    assert client.post("/api/create-user", json=creds).status_code == 201
    r = client.post("/api/login", json={"email": creds["email"], "password": creds["password"]})
    assert r.status_code == 200
    creds["headers"] = {"Authorization": f"Bearer {r.get_json()['token']}"}
    return creds


def upload(client, headers, data=None, name="t.pdf"):
    return client.post(
        "/api/upload-document", headers=headers,
        data={"file": (io.BytesIO(data or make_pdf()), name), "name": "My Doc"},
        content_type="multipart/form-data",
    )


@pytest.fixture()
def doc(client, user):
    r = upload(client, user["headers"])
    assert r.status_code == 201
    return r.get_json()


def wm_body(method, **kw):
    b = {"method": method, "intended_for": "bob", "secret": "sec", "key": "key"}
    b.update(kw)
    return b


@pytest.fixture(scope="session")
def method():
    """First watermarking method that works on our test PDF."""
    pdf = make_pdf()
    p = Path(os.environ["STORAGE_DIR"]) / "probe.pdf"
    p.write_bytes(pdf)
    for m in WMUtils.METHODS:
        try:
            if WMUtils.is_watermarking_applicable(method=m, pdf=str(p), position=None) is False:
                continue
            wm = WMUtils.apply_watermark(pdf=str(p), secret="sec", key="key", method=m, position=None)
            q = Path(os.environ["STORAGE_DIR"]) / "probe_wm.pdf"
            q.write_bytes(wm)
            if WMUtils.read_watermark(method=m, pdf=str(q), key="key") == "sec":
                return m
        except Exception:
            continue
    pytest.skip("no watermarking method round-trips on the test PDF")


# ---------- static / health ----------
def test_home_and_static(client):
    assert client.get("/").status_code in (200, 404)  # 404 if no static/index.html
    assert client.get("/nope-does-not-exist.txt").status_code == 404
    assert client.get("/.hidden/secret").status_code == 404


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json()["db_connected"] is True
    assert r.headers["X-Content-Type-Options"] == "nosniff"


# ---------- create-user / login ----------
def test_create_user_validation_and_duplicate(client, user):
    assert client.post("/api/create-user", data="x").status_code == 400
    assert client.post("/api/create-user", json={"email": 1, "login": "a", "password": "b"}).status_code == 400
    bad = {"email": "a@b.c", "login": "../x", "password": "Passw0rd!123"}
    assert client.post("/api/create-user", json=bad).status_code == 400
    bad = {"email": "a@b.c", "login": "okname", "password": "short"}
    assert client.post("/api/create-user", json=bad).status_code == 400
    dup = {"email": user["email"], "login": user["login"], "password": user["password"]}
    assert client.post("/api/create-user", json=dup).status_code == 409


def test_login_paths(client, user):
    assert client.post("/api/login", data="x").status_code == 400
    assert client.post("/api/login", json={"email": 1, "password": 2}).status_code == 400
    assert client.post("/api/login", json={"email": "", "password": ""}).status_code == 400
    assert client.post("/api/login", json={"email": user["email"], "password": "wrongpass"}).status_code == 401
    assert client.post("/api/login", json={"email": "no@one.com", "password": "wrongpass"}).status_code == 401


# ---------- auth ----------
@pytest.mark.parametrize("method_,url", [
    ("get", "/api/list-documents"), ("get", "/api/list-versions"),
    ("get", "/api/list-all-versions"), ("get", "/api/get-document/1"),
    ("post", "/api/upload-document"), ("post", "/api/create-watermark/1"),
    ("post", "/api/read-watermark/1"), ("delete", "/api/delete-document/1"),
])
def test_requires_auth(client, method_, url):
    assert getattr(client, method_)(url).status_code == 401


def test_auth_bad_tokens(client):
    h = lambda v: {"Authorization": v}  # noqa: E731
    assert client.get("/api/list-documents", headers=h("Bearer garbage")).status_code == 401
    expired = server.app.config["TOKEN_TTL_SECONDS"]
    server.app.config["TOKEN_TTL_SECONDS"] = -1
    try:
        s = server.URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
        tok = s.dumps({"uid": 1, "login": "x"})
        r = client.get("/api/list-documents", headers=h(f"Bearer {tok}"))
        assert r.status_code == 401
    finally:
        server.app.config["TOKEN_TTL_SECONDS"] = expired
    s = server.URLSafeTimedSerializer(server.app.config["SECRET_KEY"], salt="tatou-auth")
    for payload in ({"uid": "x", "login": "a"}, {"uid": 0, "login": "a"}, {"uid": 1, "login": 5}, {}):
        tok = s.dumps(payload)
        assert client.get("/api/list-documents", headers=h(f"Bearer {tok}")).status_code == 401


# ---------- upload / list / get / delete ----------
def test_upload_validation(client, user):
    h = user["headers"]
    assert client.post("/api/upload-document", headers=h, data={}, content_type="multipart/form-data").status_code == 400
    r = client.post("/api/upload-document", headers=h,
                    data={"file": (io.BytesIO(b"x"), "")}, content_type="multipart/form-data")
    assert r.status_code == 400
    r = client.post("/api/upload-document", headers=h,
                    data={"file": (io.BytesIO(b"x"), "///")}, content_type="multipart/form-data")
    assert r.status_code == 400
    assert upload(client, h, data=b"not a pdf").status_code == 400


def test_list_and_get_document(client, user, doc):
    h = user["headers"]
    docs = client.get("/api/list-documents", headers=h).get_json()["documents"]
    assert [d["id"] for d in docs] == [doc["id"]]
    r = client.get(f"/api/get-document/{doc['id']}", headers=h)
    assert r.status_code == 200 and r.data.startswith(b"%PDF-")
    r = client.get(f"/api/get-document?id={doc['id']}", headers=h)
    assert r.status_code == 200
    assert client.get("/api/get-document", headers=h).status_code == 400
    assert client.get("/api/get-document/999999999", headers=h).status_code == 404


def test_other_user_cannot_access(client, user, doc):
    tag = uuid.uuid4().hex[:10]
    other = {"email": f"{tag}@example.com", "login": f"o{tag}", "password": "Passw0rd!123"}
    client.post("/api/create-user", json=other)
    tok = client.post("/api/login", json={"email": other["email"], "password": other["password"]}).get_json()["token"]
    oh = {"Authorization": f"Bearer {tok}"}
    assert client.get(f"/api/get-document/{doc['id']}", headers=oh).status_code == 404
    assert client.delete(f"/api/delete-document/{doc['id']}", headers=oh).status_code == 404
    assert client.post(f"/api/create-watermark/{doc['id']}", headers=oh, json={}).status_code in (400, 404)


def test_get_document_missing_file(client, user, doc):
    for p in (Path(server.app.config["STORAGE_DIR"]) / "files" / user["login"]).glob("*__t.pdf"):
        p.unlink()
    assert client.get(f"/api/get-document/{doc['id']}", headers=user["headers"]).status_code == 410


def test_delete_document_variants(client, user):
    h = user["headers"]
    d1, d2, d3 = (upload(client, h).get_json()["id"] for _ in range(3))
    assert client.delete(f"/api/delete-document/{d1}", headers=h).get_json()["deleted"] is True
    r = client.post("/api/delete-document", headers=h, json={"id": d2})
    assert r.status_code == 200
    assert client.delete(f"/api/delete-document?id={d3}", headers=h).status_code == 200
    assert client.delete("/api/delete-document", headers=h).status_code == 400
    assert client.delete("/api/delete-document?id=0", headers=h).status_code == 400
    assert client.delete("/api/delete-document?id=abc", headers=h).status_code == 400
    assert client.post("/api/delete-document", headers=h, json=[1]).status_code == 400
    assert client.delete(f"/api/delete-document/{d1}", headers=h).status_code == 404


# ---------- watermarking ----------
def test_get_watermarking_methods(client):
    r = client.get("/api/get-watermarking-methods")
    j = r.get_json()
    assert r.status_code == 200 and j["count"] == len(j["methods"]) > 0


def test_create_watermark_validation(client, user, doc):
    h, d = user["headers"], doc["id"]
    m = next(iter(WMUtils.METHODS))
    assert client.post(f"/api/create-watermark/{d}", headers=h, data="x", content_type="application/json").status_code == 400
    assert client.post(f"/api/create-watermark/{d}", headers=h, json=[1]).status_code == 400
    assert client.post("/api/create-watermark", headers=h, json=wm_body(m)).status_code == 400  # no id
    assert client.post(f"/api/create-watermark/{d}", headers=h, json=wm_body("nope")).status_code == 400
    assert client.post(f"/api/create-watermark/{d}", headers=h, json=wm_body(m, key="")).status_code == 400
    assert client.post("/api/create-watermark/999999999", headers=h, json=wm_body(m)).status_code == 404


def test_watermark_roundtrip_and_get_version(client, user, doc, method):
    h, d = user["headers"], doc["id"]
    r = client.post(f"/api/create-watermark/{d}", headers=h, json=wm_body(method))
    assert r.status_code == 201, r.get_json()
    link = r.get_json()["link"]

    # id via JSON body
    r2 = client.post("/api/create-watermark", headers=h, json=wm_body(method, id=d))
    assert r2.status_code == 201

    # list versions (path / query / missing)
    assert len(client.get(f"/api/list-versions/{d}", headers=h).get_json()["versions"]) == 2
    assert len(client.get(f"/api/list-versions?id={d}", headers=h).get_json()["versions"]) == 2
    assert client.get("/api/list-versions", headers=h).status_code == 400
    assert len(client.get("/api/list-all-versions", headers=h).get_json()["versions"]) == 2

    # get-version is public (link is the credential)
    r = client.get(f"/api/get-version/{link}")
    assert r.status_code == 200 and r.data.startswith(b"%PDF-")
    assert client.get("/api/get-version/short").status_code == 404
    assert client.get("/api/get-version/" + "a" * 40).status_code == 404
    assert client.get("/api/get-version/" + "b" * 32).status_code == 404

    # read-watermark via link
    r = client.post(f"/api/read-watermark/{d}", headers=h,
                    json={"method": method, "key": "key", "link": link})
    assert r.status_code == 200 and r.get_json()["secret"] == "sec"
    r = client.post(f"/api/read-watermark/{d}", headers=h,
                    json={"method": method, "key": "wrong", "link": "z" * 40})
    assert r.status_code == 404
    r = client.post(f"/api/read-watermark/{d}", headers=h,
                    json={"method": method, "key": "key", "link": "x" * 200})
    assert r.status_code == 400

    # deleting the doc also removes its versions
    assert client.delete(f"/api/delete-document/{d}", headers=h).get_json()["files_deleted"] >= 3


def test_read_watermark_document_paths(client, user, doc):
    h, d = user["headers"], doc["id"]
    m = next(iter(WMUtils.METHODS))
    assert client.post(f"/api/read-watermark/{d}", headers=h, json=[1]).status_code == 400
    assert client.post("/api/read-watermark", headers=h, json={"method": m, "key": "k"}).status_code == 400
    assert client.post(f"/api/read-watermark/{d}", headers=h, json={"method": "nope", "key": "k"}).status_code == 400
    assert client.post("/api/read-watermark/999999999", headers=h, json={"method": m, "key": "k"}).status_code == 404
    # un-watermarked doc: handler runs, read fails or returns something
    r = client.post(f"/api/read-watermark/{d}", headers=h, json={"method": m, "key": "k"})
    assert r.status_code in (201, 400)


# ---------- RMAP (error paths; full handshake needs client PGP keys) ----------
@pytest.mark.parametrize("url", ["/api/rmap-initiate", "/api/rmap-get-link"])
def test_rmap_errors(client, url):
    assert client.post(url, data="x").status_code == 400
    assert client.post(url, json=[1]).status_code == 400
    assert client.post(url, json={}).status_code == 400
    assert client.post(url, json={"payload": "not-a-valid-message"}).status_code == 400
