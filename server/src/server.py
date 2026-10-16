import os
import hashlib
import re
import secrets
import uuid
import logging

from rmap import RMAPServer
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file , abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import URL, create_engine, text
from sqlalchemy.exc import IntegrityError

import watermarking_utils as WMUtils
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method

def create_app():
    app = Flask(__name__)

    # --- Config ---
    def required_secret(name: str, minimum_length: int = 32) -> str:
        value = os.environ.get(name, "")
        if len(value) < minimum_length:
            raise RuntimeError(
                f"{name} must be configured with at least {minimum_length} characters"
            )
        return value

    app.config["SECRET_KEY"] = required_secret("SECRET_KEY")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "")
    if not app.config["DB_PASSWORD"]:
        raise RuntimeError("DB_PASSWORD must be configured")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # Write ownership-check misses to a private audit log in storage.
    security_logger = logging.getLogger("tatou.security")
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    log_path = app.config["STORAGE_DIR"] / "security.log"
    if not any(
        getattr(handler, "baseFilename", None) == str(log_path)
        for handler in security_logger.handlers
    ):
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        security_logger.addHandler(handler)
    os.chmod(log_path, 0o600)

    def log_access_denied(action, doc_id):
        user = getattr(g, "user", {}) or {}
        security_logger.warning(
            "ACCESS_DENIED action=%s user=%s user_id=%s doc_id=%s ip=%s",
            action,
            user.get("login", "unknown"),
            user.get("id", "unknown"),
            doc_id,
            request.remote_addr or "unknown",
        )

    # --- DB engine only (no Table metadata) ---
    def db_url() -> URL:
        return URL.create(
            "mysql+pymysql",
            username=app.config["DB_USER"],
            password=app.config["DB_PASSWORD"],
            host=app.config["DB_HOST"],
            port=app.config["DB_PORT"],
            database=app.config["DB_NAME"],
            query={"charset": "utf8mb4"},
        )


    app.config["RMAP_SERVER_PUB"] = Path(os.environ.get("RMAP_SERVER_PUB", "./keys/server_pub.asc")).resolve()
    app.config["RMAP_SERVER_PRIV"] = Path(os.environ.get("RMAP_SERVER_PRIV", "./keys/server_priv.asc")).resolve()
    app.config["RMAP_CLIENTS_DIR"] = Path(os.environ.get("RMAP_CLIENTS_DIR", "./keys/clients/pki")).resolve()
    # RMAP's result field is the nonce-derived 32-character token only.
    app.config["RMAP_LINK_PREFIX"] = ""
    app.config["RMAP_SERVER_KEY_PASSPHRASE"] = os.environ.get("RMAP_SERVER_KEY_PASSPHRASE", "")
    app.config["RMAP_WATERMARK_KEY"] = required_secret("RMAP_WATERMARK_KEY")
    app.config["RMAP_SOURCE_DOCUMENT_ID"] = int(
        os.environ.get("RMAP_SOURCE_DOCUMENT_ID", "3")
    )


    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng



    def get_rmap_server():
        rs = app.config.get("_RMAP_SERVER")
        if rs is None:
            rs = RMAPServer(
                app.config["RMAP_SERVER_PUB"],
                app.config["RMAP_SERVER_PRIV"],
                passphrase=app.config["RMAP_SERVER_KEY_PASSPHRASE"] or None,
                linkPrefix=app.config["RMAP_LINK_PREFIX"],
                verbose=False,
            )
            rs.loadIdentities(app.config["RMAP_CLIENTS_DIR"])
            app.config["_RMAP_SERVER"] = rs
        return rs

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            try:
                user_id = int(data["uid"])
                login = data["login"]
            except (KeyError, TypeError, ValueError):
                return _auth_error("Invalid token")
            if user_id <= 0 or not isinstance(login, str):
                return _auth_error("Invalid token")
            g.user = {"id": user_id, "login": login, "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _resolve_under(root: Path, path_value: str | os.PathLike[str]) -> Path:
        root = Path(root).resolve()
        candidate = Path(path_value)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise ValueError("path is outside allowed directory")
        return resolved

    def _safe_resolve_under_storage(path_value):
        return _resolve_under(app.config["STORAGE_DIR"], path_value)

    def _user_dir(user_id: int) -> Path:
        # Preserve the username-based storage layout used by existing documents.
        with get_engine().connect() as conn:
            row = conn.execute(
                text("SELECT login FROM Users WHERE id = :uid"),
                {"uid": int(user_id)},
            ).first()
        if not row or not isinstance(row.login, str) or not row.login:
            raise ValueError("User storage directory cannot be resolved")
        return _resolve_under(
            app.config["STORAGE_DIR"] / "files",
            app.config["STORAGE_DIR"] / "files" / row.login,
        )

    class _NotOwned(Exception):
        pass

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        if any(part.startswith(".") for part in Path(filename).parts):
            abort(404)
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True)

        # FZ-001: Validate JSON structure and field types
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400

        if not all(
            isinstance(payload.get(field), str)
            for field in ("email", "login", "password")
        ):
            return jsonify({
                "error": "email, login, and password must be strings"
            }), 400

        email = payload["email"].strip().lower()
        login = payload["login"].strip()
        password = payload["password"]
        if (
            not email
            or len(email) > 254
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", login)
            or login in {".", ".."}
            or not 8 <= len(password) <= 1024
        ):
            return jsonify({"error": "invalid email, login, or password length"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception:
            app.logger.exception("Database error creating user")
            return jsonify({"error": "database error"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True)

        # FZ-002: Validate login JSON and field types
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400

        if not all(
            isinstance(payload.get(field), str)
            for field in ("email", "password")
        ):
            return jsonify({
                "error": "email and password must be strings"
            }), 400

        email = payload["email"].strip().lower()
        password = payload["password"]

        if not email or not password or len(email) > 254 or len(password) > 1024:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception:
            app.logger.exception("Database error during login")
            return jsonify({"error": "database error"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = secure_filename(file.filename)
        if not fname:
            return jsonify({"error": "invalid filename"}), 400
        if not file.stream.read(5).startswith(b"%PDF-"):
            return jsonify({"error": "only PDF files are accepted"}), 400
        file.stream.seek(0)

        user_dir = _user_dir(g.user["id"])
        user_dir.mkdir(parents=True, exist_ok=True)

        final_name = secure_filename((request.form.get("name") or fname).strip())
        if not final_name:
            final_name = fname
        final_name = final_name[:180]
        stored_name = f"{uuid.uuid4().hex}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception:
            app.logger.exception("Database error saving uploaded document")
            stored_path.unlink(missing_ok=True)
            return jsonify({"error": "database error"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception:
            app.logger.exception("Database error listing documents")
            return jsonify({"error": "database error"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Documents d
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.ownerid = :uid AND d.id = :did
                    """),
                    {"uid": int(g.user["id"]), "did": document_id},
                ).all()
        except Exception:
            app.logger.exception("Database error listing document versions")
            return jsonify({"error": "database error"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200


    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Documents d
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.ownerid = :uid
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception:
            app.logger.exception("Database error listing all versions")
            return jsonify({"error": "database error"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("Database error fetching document")
            return jsonify({"error": "database error"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            log_access_denied("get_document", document_id)
            return jsonify({"error": "document not found"}), 404

        try:
            file_path = _safe_resolve_under_storage(row.path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        # RMAP links are 32 hex characters; application-issued links are 40.
        # Reject legacy predictable SHA-1 filename links.
        if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40})", link):
            return jsonify({"error": "document not found"}), 404

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT v.link, v.path, d.ownerid
                        FROM Versions v
                        JOIN Documents d ON d.id = v.documentid
                        WHERE v.link = :link
                        LIMIT 1
                    """),
                    {"link": link},
             ).first()
        except Exception:
            app.logger.exception("Database error fetching version")
            return jsonify({"error": "database error"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        # Old application links were SHA-1 hashes of predictable filenames.
        # Refuse those links even before the one-time link rotation is run.
        if len(link) == 40:
            legacy = hashlib.sha1(Path(row.path).name.encode("utf-8")).hexdigest()
            if secrets.compare_digest(link.lower(), legacy):
                return jsonify({"error": "document not found"}), 404

        try:
            file_path = _resolve_under(_user_dir(row.ownerid) / "watermarks", row.path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "no-store"
        return resp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth

    def delete_document(document_id: int | None = None):
        payload = request.get_json(silent=True) if request.is_json else None
        if payload is not None and not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (payload or {}).get("id")
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
        if doc_id <= 0:
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        uid = int(g.user["id"])
        try:
            with get_engine().begin() as conn:
                doc = conn.execute(
                    text("SELECT path FROM Documents WHERE id = :id AND ownerid = :uid FOR UPDATE"),
                    {"id": doc_id, "uid": uid},
                ).first()
                if not doc:
                    raise _NotOwned()
                versions = conn.execute(
                    text("""
                        SELECT v.path FROM Versions v
                        JOIN Documents d ON d.id = v.documentid
                        WHERE d.id = :id AND d.ownerid = :uid
                    """),
                    {"id": doc_id, "uid": uid},
                ).all()
                conn.execute(
                    text("""
                        DELETE v FROM Versions v
                        JOIN Documents d ON d.id = v.documentid
                        WHERE d.id = :id AND d.ownerid = :uid
                    """),
                    {"id": doc_id, "uid": uid},
                )
                result = conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": uid},
                )
                if result.rowcount != 1:
                    raise _NotOwned()
        except _NotOwned:
            log_access_denied("delete_document", doc_id)
            return jsonify({"error": "document not found"}), 404
        except Exception:
            app.logger.exception("Database error deleting document")
            return jsonify({"error": "database error"}), 503

        deleted_files = 0
        user_root = _user_dir(uid)
        for stored_path in [doc.path, *(v.path for v in versions)]:
            try:
                file_path = _resolve_under(user_root, stored_path)
                if file_path.is_file():
                    file_path.unlink()
                    deleted_files += 1
            except (OSError, TypeError, ValueError):
                app.logger.warning("Could not safely remove a document file")

        return jsonify({"deleted": True, "id": doc_id, "files_deleted": deleted_files}), 200


    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        payload = request.get_json(silent=True) if request.is_json else {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or payload.get("id")
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if (
            not isinstance(method, str)
            or method not in WMUtils.METHODS
            or not isinstance(intended_for, str)
            or not intended_for.strip()
            or len(intended_for) > 128
            or not isinstance(secret, str)
            or not secret
            or len(secret) > 4096
            or not isinstance(key, str)
            or not key
            or len(key) > 4096
        ):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("Database error creating watermark")
            return jsonify({"error": "database error"}), 503

        if not row:
            log_access_denied("create_watermark", doc_id)
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        try:
            file_path =_resolve_under(_user_dir(g.user["id"]), row.path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception:
            app.logger.exception("Watermark applicability check failed")
            return jsonify({"error": "watermark applicability check failed"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception:
            app.logger.exception("Watermark generation failed")
            return jsonify({"error": "watermarking failed"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = secure_filename(Path(row.name or file_path.name).stem) or "document"
        intended_slug = secure_filename(intended_for.strip()) or "recipient"
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}__{uuid.uuid4().hex}.pdf"
        try:
            dest_path = _safe_resolve_under_storage(dest_dir / candidate)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "watermark destination path invalid"}), 500

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception:
            app.logger.exception("Failed to write watermarked document")
            return jsonify({"error": "failed to write watermarked file"}), 500

        # The link is a bearer credential; use an unpredictable token.
        link_token = secrets.token_hex(20)

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception:
            app.logger.exception("Database error recording watermark version")
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": "database error"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201


    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})

        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        payload = request.get_json(silent=True) if request.is_json else {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or payload.get("id")
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400


        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if (
            not isinstance(method, str)
            or method not in WMUtils.METHODS
            or not isinstance(key, str)
            or not key
            or len(key) > 4096
        ):
            return jsonify({"error": "method, and key are required"}), 400

        link = payload.get("link")

        if link:
            if not isinstance(link, str) or len(link) > 128:
                return jsonify({"error": "invalid version link"}), 400
            try:
                with get_engine().connect() as conn:
                    row = conn.execute(
                        text("""
                            SELECT v.path FROM Versions v
                            JOIN Documents d ON d.id = v.documentid
                            WHERE v.link = :link AND d.ownerid = :uid
                            LIMIT 1
                        """),
                        {"link": link, "uid": int(g.user["id"])},
                    ).first()
            except Exception:
                app.logger.exception("Database error reading version watermark")
                return jsonify({"error": "database error"}), 503

            if not row:
                log_access_denied("read_watermark_version", "via-link")
                return jsonify({"error": "version not found"}), 404

            try:
                file_path =_resolve_under(_user_dir(g.user["id"]), row.path)
            except (TypeError, ValueError, OSError):
                return jsonify({"error": "version path invalid"}), 500
            if not file_path.exists():
                return jsonify({"error": "file missing on disk"}), 410

            try:
                secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
            except Exception:
                app.logger.exception("Failed to read version watermark")
                return jsonify({"error": "could not read watermark"}), 400

            return jsonify({"link": link, "secret": secret, "method": method, "position": position}), 200

        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400

        # Look up the document and enforce ownership.
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("Database error reading document watermark")
            return jsonify({"error": "database error"}), 503

        if not row:
            log_access_denied("read_watermark_document", doc_id)
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        try:
            file_path =_resolve_under(_user_dir(g.user["id"]), row.path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception:
            app.logger.exception("Failed to read document watermark")
            return jsonify({"error": "could not read watermark"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201


    # POST /api/rmap-initiate  {"payload": "<base64>"}  → Response 1
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        wire_msg1 = {"payload": payload.get("payload")}
        if not wire_msg1["payload"]:
            return jsonify({"error": "payload is required"}), 400

        try:
            identity, resp1 = get_rmap_server().receiveMsg1(wire_msg1)
        except Exception:
            app.logger.info("RMAP initiate rejected a handshake")
            return jsonify({"error": "rmap-initiate failed"}), 400

        return jsonify(resp1), 200

    # POST /api/rmap-get-link  {"payload": "<base64>"}  → Response 2 (link)
    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object required"}), 400
        wire_msg2 = {"payload": payload.get("payload")}
        if not wire_msg2["payload"]:
            return jsonify({"error": "payload is required"}), 400

        try:
            identity, expected_link, resp2 = get_rmap_server().receiveMsg2(wire_msg2)
        except Exception:
            app.logger.info("RMAP get-link rejected a handshake")
            return jsonify({"error": "rmap-get-link failed"}), 400

        if (
            not isinstance(identity, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", identity)
            or not isinstance(expected_link, str)
            or not re.fullmatch(r"[0-9a-fA-F]{32}", expected_link)
        ):
            app.logger.warning("RMAP server produced an invalid identity or link")
            return jsonify({"error": "invalid RMAP link"}), 400


        RMAP_SOURCE_DOCUMENT_ID = app.config["RMAP_SOURCE_DOCUMENT_ID"]

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": RMAP_SOURCE_DOCUMENT_ID},
                ).first()
        except Exception:
            app.logger.exception("Database error loading RMAP source document")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "rmap source document not configured"}), 500

        try:
            file_path = _safe_resolve_under_storage(row.path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "rmap source path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "rmap source file missing on disk"}), 500

        # Watermark the document, embedding the requester's identity as the secret
        try:
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=identity,
                key=app.config["RMAP_WATERMARK_KEY"],
                method="invisible-text",
                position=None,
            )
        except Exception:
            app.logger.exception("RMAP watermark generation failed")
            return jsonify({"error": "watermarking failed"}), 500

        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / f"rmap__{identity}__{expected_link}.pdf"
        try:
            dest_path = _safe_resolve_under_storage(dest_path)
        except (TypeError, ValueError, OSError):
            return jsonify({"error": "RMAP destination path invalid"}), 500
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception:
            app.logger.exception("Failed to write RMAP watermarked file")
            return jsonify({"error": "failed to write watermarked file"}), 500

        # Record the version BEFORE returning the link
        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": RMAP_SOURCE_DOCUMENT_ID,
                        "link": expected_link,
                        "intended_for": identity,
                        "secret": "",
                        "method": "invisible-text",
                        "position": "",
                        "path": str(dest_path),
                    },
                )
        except Exception:
            app.logger.exception("Database error recording RMAP version")
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": "database error"}), 503




        # TODO: create the watermarked PDF for `identity` here, and insert a
        # Versions row with link=expected_link, BEFORE returning resp2.
        return jsonify(resp2), 200

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
