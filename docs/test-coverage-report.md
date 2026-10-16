# Test Coverage Report

## 1. Overview

The Tatou automated test suite was executed using pytest and
pytest-cov against the server source code.

## 2. Test Execution Results

- Tests passed: 55
- Total statements measured: 1,236
- Statements covered: 468
- Statements missed: 768
- Overall statement coverage: 38%

## 3. Component Coverage

| Component | Coverage |
|---|---:|
| add_after_eof.py | 80% |
| invisible_text_watermark.py | 80% |
| metadata_watermark.py | 83% |
| unsafe_bash_bridge_append_eof.py | 95% |
| watermarking_method.py | 80% |
| whitespace_watermark.py | 78% |
| server.py | 25% |
| watermarking_utils.py | 33% |
| extract_watermarks.py | 0% |
| read_watermarks.py | 0% |
| rotate_legacy_version_links.py | 0% |
| watermarking_cli.py | 0% |

## 4. Analysis

The watermarking implementations have coverage between 78% and
95%. The unsafe Bash bridge implementation has the highest
coverage at 95%.

The main server module has 25% coverage, indicating that many
statements and API execution paths were not exercised.

The utility scripts with 0% coverage were not exercised by this
test run. This does not establish whether those scripts work
correctly or incorrectly.

## 5. Limitations

Statement coverage measures executed code, not overall security
or complete functional correctness.

These results alone do not prove that access control, IDOR
protection, document deletion, or every API endpoint behaves
correctly.

## 6. Recommended Improvements

1. Expand document ownership and cross-user access tests.
2. Test unauthorized deletion and watermark operations.
3. Cover successful and unsuccessful API requests.
4. Test RMAP handshakes, version creation, and PDF retrieval.
5. Add tests for currently untested utility scripts.
6. Rerun the suite and update the coverage figures after changes.
