# Security Requirements Traceability

**Threat source:** Assurance Assignment, Appendix A — Access Control

| Threat | Security requirement | Verification evidence | Remaining gap |
|---|---|---|---|
| **T.CROSS_USER:** An authenticated user accesses, modifies, or deletes another user's document or watermark version. | **Platform specification:** “Documents without watermarks MUST be accessible only to their owner (and the platform).” | **Existing tests:** `test_api.py::test_healthz_route` checks that `GET /healthz` returns status 200 and JSON; it does not test ownership. The watermark tests check watermark behavior and wrong-key handling, not cross-user API access. **Manual test reported by the CC specialist:** User A's `GET /api/get-document/627` returned `200 OK`; User B's request returned `404 NOT FOUND`. User B's `DELETE /api/delete-document/627` returned `404 NOT FOUND`, and User A could still retrieve the document afterward. | No automated cross-user document-access test was identified in the reviewed `server/test/` suite. The manual test covers only the reported document and GET/DELETE operations; other endpoints and watermark-version access remain unverified. |