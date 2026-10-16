# Specification-to-Test Mapping

## 1. Purpose

This document maps the 11 requirements in
`Platform_specifications.md` to the available automated tests
and recorded verification evidence.

The presence of a test or log does not automatically establish
that a requirement passes. Results must be checked against the
actual assertions and recorded responses.

## 2. Requirement Mapping

| ID | Specification requirement | Relevant tests or evidence | Current assessment |
|---|---|---|---|
| SPEC-01 | Users SHOULD be able to upload documents. | `server/src/server.py` upload-document route; `test_api.py` | Not directly covered by the listed test functions; add upload tests. |
| SPEC-02 | Documents without watermarks MUST be accessible only to their owner and the platform. | `artifacts/logs/cross-user-access.txt`; `artifacts/logs/unauthorized-watermark-read.txt`; ownership checks in `server.py` | Manual evidence available; inspect responses and add automated cross-user tests. |
| SPEC-03 | Users SHOULD be able to generate watermarked versions of their documents. | `test_watermarking_all_methods.py`; `test_metadata_watermark.py`; `artifacts/logs/rmap-versions.txt` | Watermark implementations are tested; end-to-end API generation needs separate verification. |
| SPEC-04 | Watermarks SHOULD be hard to remove. | `test_watermarking_all_methods.py`; `test_metadata_watermark.py`; `test_unsafe_bash_bridge.py` | Watermark creation and recovery are tested; resistance to removal has not been established by these tests alone. |
| SPEC-05 | Watermarks MUST allow the owner to retrieve the secret and identify the document version. | `test_watermarking_all_methods.py`; `test_metadata_watermark.py`; `artifacts/logs/unauthorized-watermark-read.txt` | Method-level recovery is tested; authenticated owner retrieval and version identification need explicit verification. |
| SPEC-06 | The platform SHOULD create a secret link for each watermarked document, and the link SHOULD not be guessable. | RMAP handshake verification; `artifacts/logs/rmap-versions.txt`; `server/src/server.py` version creation and retrieval routes | RMAP operation has been manually exercised; link unpredictability and access controls need dedicated tests. |
| SPEC-07 | Anyone who knows the link MAY download a watermarked document. | `/api/get-version/<link>` route; recorded successful PDF download | A successful download was manually demonstrated; add automated tests for valid and invalid links. |
| SPEC-08 | Original document metadata SHOULD be confidential to the owner and platform. | `artifacts/logs/cross-user-access.txt`; `artifacts/logs/security.log`; ownership-filtered database queries in `server.py` | Partial evidence; verify cross-user access to document lists, versions, names, sizes, and identifiers. |
| SPEC-09 | Documents SHOULD be available to their owner. | `/api/get-document` route; document storage and retrieval logic in `server.py` | Owner retrieval requires a dedicated positive test; the current test inventory does not establish it. |
| SPEC-10 | Documents SHOULD be removable by their owner. | `artifacts/logs/unauthorized-delete.txt`; delete-document route in `server.py` | Unauthorized deletion evidence exists; verify that the owner can delete successfully and another user cannot. |
| SPEC-11 | Documents SHOULD not be modifiable by third parties. | `artifacts/logs/cross-user-access.txt`; ownership checks in document and watermark routes | Partial evidence; add tests proving that another user cannot alter or delete the document or its versions. |

## 3. Existing Automated Test Inventory

| Test file | Main purpose |
|---|---|
| `test_api.py` | Basic API health check |
| `test_fuzz_create_user.py` | Invalid account-creation input |
| `test_fuzz_json_bodies.py` | Invalid JSON body shapes |
| `test_fuzz_login.py` | Invalid login input |
| `test_fuzz_missing_fields.py` | Missing required API fields |
| `test_hypothesis_create_user.py` | Property-based account-creation input tests |
| `test_hypothesis_login.py` | Property-based login input tests |
| `test_metadata_watermark.py` | Metadata watermark round-trip, wrong key, and missing secret |
| `test_unsafe_bash_bridge.py` | Watermark round-trip, shell metacharacters, and missing EOF marker |
| `test_watermarking_all_methods.py` | Applicability, watermark creation, and secret recovery across registered methods |

## 4. Evidence and Limitations

The test suite previously completed with 55 passing tests
and 38% statement coverage.

Coverage is a measure of executed code, not proof that every
requirement is satisfied.

The following evidence should be checked before assigning a
final pass status:

1. Actual HTTP status codes and response bodies in security logs.
2. Positive and negative tests for document ownership.
3. Successful owner-only document retrieval and deletion.
4. Cross-user access to document metadata and versions.
5. Watermark creation and recovery through the API.
6. Secret-link behaviour for valid, invalid, and unknown links.
7. Tests showing that third parties cannot modify or delete documents.

## 5. Conclusion

The project contains automated tests for input validation and
several watermarking methods, alongside manually recorded
security verification evidence.

However, the existing test inventory does not independently
demonstrate that all 11 platform requirements are satisfied.
Additional targeted tests and evidence review are needed before
final compliance claims can be made.
