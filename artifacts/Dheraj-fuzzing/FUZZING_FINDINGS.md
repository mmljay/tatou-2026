# Fuzzing and Property-Based Testing — Specialisation Artifacts

## Objective
Evaluate the input validation of Tatou's user registration and login API endpoints using parameterised negative-input tests and Hypothesis property-based testing.

## Scope
Endpoints tested:
- POST /api/create-user
- POST /api/login

## Testing Methods
1. Parameterised pytest tests supplied invalid email types, non-object JSON request bodies, and missing or empty required fields.
2. Hypothesis generated invalid values, including integers, booleans, lists, dictionaries and null values where configured.
3. The expected behaviour was an HTTP 400 Bad Request response for invalid inputs.

## Test Files
- test_fuzz_create_user.py
- test_fuzz_json_bodies.py
- test_fuzz_login.py
- test_fuzz_missing_fields.py
- test_hypothesis_create_user.py
- test_hypothesis_login.py

## Execution Results
Date: 17 October 2026
Environment: Linux, Python 3.13.5, pytest 9.1.1, Hypothesis 6.169.0

- Collected: 33 pytest cases
- Passed: 33
- Failed: 0
- Warning: One third-party Python 3.13 deprecation warning

The three Hypothesis test functions each configure a maximum of 100 generated examples per execution.

## Findings
All tested invalid-input cases returned the expected HTTP 400 status code. The tests provide evidence that the registration and login endpoints reject the specified malformed request bodies, invalid field types, and missing or empty required values.

## Limitations
These tests focus on input validation for two endpoints. They do not establish complete API security, full authentication correctness, or comprehensive vulnerability coverage.

## Supporting Evidence
- Six test_*.py files in this folder
- fuzzing-test-results.txt — saved pytest execution output
