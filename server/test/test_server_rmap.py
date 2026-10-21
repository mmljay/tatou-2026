"""Full RMAP handshake tests for /api/rmap-initiate and /api/rmap-get-link.

Plays the RMAP client with Group 17's own key against the Flask app.
Put next to test_server_routes.py (server/test/) and run from server/.
"""
import sys
from pathlib import Path

import pytest
from rmap import RMAPClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402
import watermarking_utils as WMUtils  # noqa: E402
from test_server_routes import client, user, make_pdf, upload  # noqa: E402,F401

KEYS = Path(__file__).resolve().parents[1] / "keys"
IDENTITY = "Group_17"
CLIENT_PRIV = KEYS / "group17_private.asc"
SERVER_PUB = KEYS / "server_pub.asc"
SERVER_PRIV = KEYS / "server_priv.asc"
CLIENTS_DIR = KEYS / "clients" / "pki"

pytestmark = pytest.mark.skipif(
    not (CLIENT_PRIV.exists() and SERVER_PUB.exists() and SERVER_PRIV.exists()),
    reason="RMAP key files not found in server/keys",
)


@pytest.fixture()
def rmap_cfg():
    """Point the app at the known keys and force a fresh RMAPServer."""
    app = server.app
    names = ["RMAP_SERVER_PUB", "RMAP_SERVER_PRIV", "RMAP_CLIENTS_DIR",
             "RMAP_SERVER_KEY_PASSPHRASE", "RMAP_SOURCE_DOCUMENT_ID", "_RMAP_SERVER"]
    saved = {k: app.config.get(k) for k in names}
    app.config.update(
        RMAP_SERVER_PUB=SERVER_PUB,
        RMAP_SERVER_PRIV=SERVER_PRIV,
        RMAP_CLIENTS_DIR=CLIENTS_DIR,
        RMAP_SERVER_KEY_PASSPHRASE="",
        _RMAP_SERVER=None,
    )
    yield app
    app.config.update(saved)


def handshake(client, identity=IDENTITY):
    c = RMAPClient(identity, CLIENT_PRIV, SERVER_PUB, passphrase=None)
    r1 = client.post("/api/rmap-initiate", json=c.build_msg1())
    if r1.status_code != 200:
        return c, r1, None
    c.process_resp1(r1.get_json())
    r2 = client.post("/api/rmap-get-link", json=c.build_msg2())
    return c, r1, r2


@pytest.fixture()
def source_doc(client, user, rmap_cfg, tmp_path):
    """Upload a PDF and make it the RMAP source document."""
    probe = tmp_path / "probe.pdf"
    probe.write_bytes(make_pdf())
    try:
        WMUtils.apply_watermark(pdf=str(probe), secret="x",
                                key=rmap_cfg.config["RMAP_WATERMARK_KEY"],
                                method="invisible-text", position=None)
    except Exception as e:  # test PDF not accepted by this method
        pytest.skip(f"invisible-text cannot watermark the test PDF: {e}")
    r = upload(client, user["headers"])
    assert r.status_code == 201
    doc_id = r.get_json()["id"]
    rmap_cfg.config["RMAP_SOURCE_DOCUMENT_ID"] = doc_id
    yield doc_id
    client.delete(f"/api/delete-document/{doc_id}", headers=user["headers"])


def test_full_handshake_and_download(client, source_doc):
    c, r1, r2 = handshake(client)
    assert r1.status_code == 200
    assert r2.status_code == 200, r2.get_json()
    link = c.process_resp2(r2.get_json())
    assert link == c.expected_link
    assert len(link) == 32
    r = client.get(f"/api/get-version/{link}")
    assert r.status_code == 200 and r.data.startswith(b"%PDF-")


def test_unknown_identity_rejected(client, rmap_cfg):
    _, r1, r2 = handshake(client, identity="Nobody_Here")
    assert r1.status_code == 400 and r2 is None


def test_source_document_not_configured(client, rmap_cfg):
    rmap_cfg.config["RMAP_SOURCE_DOCUMENT_ID"] = 2147483646
    _, r1, r2 = handshake(client)
    assert r1.status_code == 200
    assert r2.status_code == 500


def test_source_file_missing_on_disk(client, user, rmap_cfg):
    r = upload(client, user["headers"])
    doc_id = r.get_json()["id"]
    for p in (Path(server.app.config["STORAGE_DIR"]) / "files" / user["login"]).glob("*__t.pdf"):
        p.unlink()
    rmap_cfg.config["RMAP_SOURCE_DOCUMENT_ID"] = doc_id
    _, r1, r2 = handshake(client)
    assert r1.status_code == 200
    assert r2.status_code == 500
    client.delete(f"/api/delete-document/{doc_id}", headers=user["headers"])
