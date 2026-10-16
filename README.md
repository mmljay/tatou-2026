# Tatou — PDF Watermarking Platform

Tatou is a web-based platform for uploading PDF documents, generating watermarked versions, and retrieving watermark secrets to help identify document versions.

This project is intended for educational use and contains security vulnerabilities. It must not be deployed on an open or untrusted network.

## 1. Project Overview

The project combines PDF watermarking techniques, a Flask API, database-backed document and version management, and the RMAP protocol for generating links to watermarked versions.

The project covers two main phases:

- **Phase I — Platform and Watermarking:** Implementation and integration of watermarking methods, document and version management, and RMAP functionality.
- **Phase II — Security Testing and Hardening:** Input validation, automated testing, access-control improvements, security incident investigation, and deployment hardening.

## 2. Watermarking Methods

The platform includes five watermarking implementations:

- **Toy EOF (`toy-eof`):** Appends a watermark record after the PDF EOF marker, using HMAC-SHA256.
- **Invisible text (`invisible-text`):** Embeds identifying information using invisible text in the PDF.
- **Whitespace (`whitespace`):** Encodes identifying information through whitespace variations.
- **Metadata (`metadata-watermark`):** Stores the watermark secret in PDF XMP metadata, protected using AES-256-GCM authenticated encryption.
- **Unsafe Bash bridge append-EOF (`unsafe-bash-bridge-append-eof`):** An EOF-based watermarking implementation that also provides a basis for testing unsafe shell-processing behaviour.

The implementations are registered in the watermarking method registry. The platform provides functionality for applying watermarks, checking applicability, and recovering watermark secrets.

Automated tests cover watermark creation, secret recovery, applicability checks, and relevant error cases, including incorrect keys and missing watermark data.

## 3. Technology Stack

- Python
- Flask
- MariaDB
- SQLAlchemy
- PyMuPDF
- Cryptography and AES-256-GCM
- RMAP protocol and PGP-based key handling
- Docker and Docker Compose
- pytest and Hypothesis

## 4. Requirements

- Git
- Python 3.12 or a compatible Python version
- Docker Engine
- Docker Compose
- A Linux environment or compatible shell

## 5. Configuration

Create a local environment file:

```bash
cp sample.env .env
```

Edit `.env` and replace example passwords and placeholders with appropriate values.

The deployment configuration uses the following variables:

- `MARIADB_ROOT_PASSWORD`
- `MARIADB_USER`
- `MARIADB_PASSWORD`
- `SECRET_KEY`
- `RMAP_WATERMARK_KEY`
- `FLAG_2`
- `RMAP_SERVER_KEY_PASSPHRASE`, if required by the configured private key
- `RMAP_LINK_PREFIX`, if required by the deployment
- `RMAP_SOURCE_DOCUMENT_ID`, if a different source document is required

Generate cryptographically random keys using:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Generate separate values for the application secret and watermark key. Configure the appropriate course-approved flag and RMAP settings for the environment.

Never commit `.env`, private keys, flag values, or sensitive backups to Git.

## 6. Running Automated Tests

From the repository root, create and activate a virtual environment and install the development dependencies:

```bash
cd server

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pip install pytest-cov

cd ..
```

Run the automated tests with isolated test configuration:

```bash
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
RMAP_WATERMARK_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
DB_PASSWORD="test-only-not-a-real-password" \
DB_PORT=1 \
DB_NAME="tatou_test_only" \
STORAGE_DIR="$(mktemp -d)" \
server/.venv/bin/python -m pytest server/test/ -q
```

The test suite includes API health checks, input-validation tests, property-based tests, and watermarking tests.

Tests requiring a running database, external service, or specific RMAP configuration may need separate setup.

## 7. Test Coverage

Generate a statement-coverage report with:

```bash
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
RMAP_WATERMARK_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
DB_PASSWORD="test-only-not-a-real-password" \
DB_PORT=1 \
DB_NAME="tatou_test_only" \
STORAGE_DIR="$(mktemp -d)" \
server/.venv/bin/python -m pytest server/test/ \
  --cov=server/src \
  --cov-report=term \
  --cov-report=html:artifacts/coverage-html -q
```

The HTML report is generated in `artifacts/coverage-html/`.

The recorded test run completed with 55 passing tests and 38% statement coverage across 1,236 statements. Coverage indicates which statements were executed; it does not prove complete correctness or security.

See:

- `docs/test-coverage-report.md`
- `docs/spec-to-test-mapping.md`

## 8. Deployment with Docker Compose

Configure `.env` before starting the services.

Validate the Compose configuration and start the application:

```bash
docker compose config
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 server db
```

Check the health endpoint:

```bash
curl -i http://localhost:5000/healthz
```

Stop the services:

```bash
docker compose down
```

Do not use `docker compose down -v` unless you intentionally want to remove persistent database and file-storage volumes.

The current Compose configuration exposes:

- `5000`: Flask API
- `3306`: MariaDB
- `8080`: phpMyAdmin

Do not expose database administration services or database ports to untrusted networks.

## 9. API Endpoints

The server implements the following routes:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/healthz` | Check service and database health |
| POST | `/api/create-user` | Create a user account |
| POST | `/api/login` | Authenticate a user |
| POST | `/api/upload-document` | Upload a document |
| GET | `/api/list-documents` | List documents |
| GET | `/api/list-versions` | List document versions |
| GET | `/api/list-all-versions` | List available versions |
| GET | `/api/get-document` | Retrieve a document |
| GET | `/api/get-version/<link>` | Retrieve a watermarked version using its link |
| POST | `/api/create-watermark` | Create a watermarked version |
| GET | `/api/get-watermarking-methods` | List registered watermarking methods |
| POST | `/api/read-watermark` | Read a watermark |
| POST | `/api/rmap-initiate` | Initiate an RMAP handshake |
| POST | `/api/rmap-get-link` | Complete the RMAP link workflow |

Consult `server/src/server.py` for route definitions, accepted parameters, and authentication requirements.

## 10. Security Testing and Hardening

Phase II work included:

- Validation of malformed JSON, missing fields, and invalid input types.
- Property-based tests for account creation and login.
- Regression tests for watermarking implementations.
- Removal of unsafe serialized-plugin loading functionality.
- Improvements to document ownership checks and upload-path handling.
- Stronger application-secret configuration and a shorter default token lifetime.
- Request-size limits and security audit logging.
- Container privilege restrictions and storage-permission corrections.
- Investigation and remediation of reported flag-capture incidents.
- Rotation of predictable version links and revocation of obsolete versions.

The project journal records the chronology of deployments, incidents, defenses, bug fixes, and flag rotations.

## 11. Documentation

- `Platform_specifications.md` — platform requirements.
- `incident-journal.md` — chronological development and security incident record.
- `docs/test-coverage-report.md` — test execution and coverage results.
- `docs/spec-to-test-mapping.md` — mapping of platform requirements to tests and evidence.

## 12. Limitations

The project is an educational security exercise and should not be treated as production-ready.

The current test coverage is limited, and not every platform requirement has been independently verified. Additional testing is needed for document ownership, cross-user access, metadata confidentiality, deletion, version-link behaviour, and all API error paths.

Successful tests and security fixes do not establish that the application is free from vulnerabilities. The original attack paths for reported flag captures were not conclusively established, and previously downloaded copies of revoked documents cannot be recalled.

Do not deploy this platform on an open or untrusted network.
