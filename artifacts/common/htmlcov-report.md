## Test Execution Results

* Tests collected: 53
* Tests passed: 47
* Tests failed: 0
* Tests skipped: 6 (in `test_watermarking_all_methods.py`)
* Total statements measured: 1,245
* Statements covered: 823
* Statements missed: 422
* Overall statement coverage: 66%
* Run time: about 6 seconds

| Test file | Tests |
|---|---:|
| test_api.py | 1 |
| test_invisible_text_watermark.py | 3 |
| test_metadata_watermark.py | 3 |
| test_unsafe_bash_bridge.py | 3 |
| test_watermarking_all_methods.py | 9 passed, 6 skipped |
| test_server_routes.py (new) | 24 |
| test_server_rmap.py (new) | 4 |

`test_idor.py` is excluded because it needs a running server.

## Coverage table

| File | Statements | Missing | Excluded | Coverage |
|---|---:|---:|---:|---:|
| src/add_after_eof.py | 70 | 12 | 0 | 83% |
| src/extract_watermarks.py | 31 | 31 | 0 | 0% |
| src/invisible_text_watermark.py | 54 | 7 | 0 | 87% |
| src/metadata_watermark.py | 113 | 18 | 0 | 84% |
| src/read_watermarks.py | 12 | 12 | 0 | 0% |
| src/rotate_legacy_version_links.py | 29 | 29 | 0 | 0% |
| **src/server.py** | **601** | **117** | **0** | **81%** |
| src/unsafe_bash_bridge_append_eof.py | 31 | 5 | 0 | 84% |
| src/watermarking_cli.py | 126 | 126 | 0 | 0% |
| src/watermarking_method.py | 41 | 8 | 0 | 80% |
| src/watermarking_utils.py | 82 | 46 | 0 | 44% |
| src/whitespace_watermark.py | 55 | 11 | 0 | 80% |
| **Total** | **1245** | **422** | **0** | **66%** |

## Routes and tests

| Route | Test |
|---|---|
| GET /, static files | test_home_and_static |
| GET /healthz | test_healthz |
| POST /api/create-user | test_create_user_validation_and_duplicate |
| POST /api/login | test_login_paths |
| POST /api/upload-document | test_upload_validation, test_list_and_get_document |
| GET /api/list-documents | test_list_and_get_document |
| GET /api/list-versions, /api/list-all-versions | test_watermark_roundtrip_and_get_version |
| GET /api/get-document | test_list_and_get_document, test_get_document_missing_file |
| GET /api/get-version/ | test_watermark_roundtrip_and_get_version |
| DELETE/POST /api/delete-document | test_delete_document_variants |
| POST /api/create-watermark | test_create_watermark_validation, test_watermark_roundtrip_and_get_version |
| GET /api/get-watermarking-methods | test_get_watermarking_methods |
| POST /api/read-watermark | test_read_watermark_document_paths, test_watermark_roundtrip_and_get_version |
| POST /api/rmap-initiate, /api/rmap-get-link | test_server_rmap.py (4 tests), test_rmap_errors |


## Analysis

**Routes.** All routes in `server.py` are now exercised. `server.py` coverage rose from 25% to 81% (484 of 601 statements covered), which addresses the missing route coverage. Success and failure paths are tested for each route: authentication, input validation, ownership checks (access to another user's document returns 404), missing files on disk (410), and the full RMAP handshake with the group key.

**Remaining gaps in `server.py` (117 statements).** These are mostly defensive branches: database errors (`except Exception` returning 503), filesystem write failures, and invalid-path handling. They are hard to trigger without mocking the database or disk.

**Where the other missed statements are (422 in total).**

| Group | Missed statements | Share of all missed |
|---|---:|---:|
| Command-line / one-off scripts with no tests (`watermarking_cli.py`, `extract_watermarks.py`, `read_watermarks.py`, `rotate_legacy_version_links.py`) | 198 | 47% |
| `server.py` | 117 | 28% |
| Watermarking modules (`watermarking_utils.py` 44%, others 80-87%) | 107 | 25% |

**Conclusion.** The overall figure of 66% is held down mainly by four scripts that are not part of the HTTP API. The API itself, which is the attack surface, is well covered. The next steps with the most benefit would be tests for `watermarking_utils.py` (46 missed) and for the CLI scripts.

## Requirements

MariaDB reachable, and env vars `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `SECRET_KEY` and `RMAP_WATERMARK_KEY` (32+ characters each). RMAP tests also need the key files in `server/keys/` and are skipped if they are missing.

## Before vs after

| | 2026-10-17 | 2026-10-21 |
|---|---:|---:|
| server.py | 25% | 81% |
| Total | 38% | 66% |
