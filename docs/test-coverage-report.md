# Test Coverage Report

## 1. Overview

The Tatou automated test suite was executed using pytest and
pytest-cov against the server source code.

## 2. Test Execution Results

- Tests passed: 52
- Tests failed: 0
- Total statements measured: 1,228
- Statements covered: 640
- Statements missed: 588
- Overall statement coverage: 52%

## 3. Component Coverage

| Component | Coverage |
|---|---:|
| add_after_eof.py | 80% |
| invisible_text_watermark.py | 79% |
| metadata_watermark.py | 83% |
| unsafe_bash_bridge_append_eof.py | 77% |
| watermarking_method.py | 80% |
| whitespace_watermark.py | 78% |
| server.py | 25% |
| watermarking_utils.py | 33% |
| test_api.py | 100% |
| test_fuzz_create_user.py | 100% |
| test_fuzz_json_bodies.py | 100% |
| test_fuzz_login.py | 100% |
| test_fuzz_missing_fields.py | 100% |
| test_hypothesis_create_user.py | 100% |
| test_hypothesis_login.py | 100% |
| test_metadata_watermark.py | 100% |
| test_watermarking_all_methods.py | 89% |

## 4. Analysis

The metadata watermark implementation achieved 83% coverage.
Other watermark implementations achieved between 77% and 80%,
while the main server module achieved 25%.

The test suite exercises input validation, account creation,
login validation, and watermark functionality. However, many
API execution paths remain untested.

## 5. Limitations

Statement coverage measures executed code. It does not prove
complete functional correctness, security, or compliance with
every platform requirement.

The six skipped watermark test cases were related to methods
reported as not applicable to the sample PDF.

The coverage run does not independently establish that every
document ownership, IDOR, deletion, or RMAP requirement passes.

## 6. Recommended Improvements

1. Expand document ownership and cross-user access tests.
2. Test unauthorized deletion and watermark operations.
3. Cover successful and unsuccessful API requests.
4. Test RMAP handshakes, version creation, and PDF retrieval.
5. Add tests for currently untested utility scripts.
6. Re-run coverage after further code changes.
