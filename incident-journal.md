
## Second Flag 1 capture — 2026-10-14T12:28:22+02:00
- Impact: The course reported another capture of Group 17's Flag 1. The replacement was rotated; its value is intentionally not recorded here.
- Likely cause: The reviewed application exposed unsafe plugin deserialization and upload paths derived from user-controlled logins, enabling a plausible route to server-side code execution. The exact request path is unconfirmed because access logs were not available.
- Response: Disabled plugin deserialization, confined uploads by user ID, added document ownership checks, rotated predictable version links, removed weak secret defaults, and restricted the container process and Flag 1 file permissions.
- Follow-up: Verify Compose mounts and secrets, rebuild the server, and confirm the service and database health.
- Deployment follow-up: patched server started; 195 predictable version links were rotated; Flag 1 permissions and database health passed. Persistent storage ownership was corrected for the non-root app user.

## Flag 3 rotation and verification — 2026-10-16
- Incident: The course reported that Group 17's Flag 3 was captured on 2026-10-11. The original exploitation path has not been confirmed.
- Scope: Identified the Flag 3 PDF belonging to Mr Important (document ID 646) and five associated watermark versions (IDs 259, 300, 345, 394, 460).
- Preservation: Created restricted-access backups of the original document, watermark files, and database before making changes. Backups and flag values are excluded from this journal.
- Rotation: Generated a fresh random 40-character hexadecimal flag, replaced the original PDF content, and updated the document's database SHA-256 and size metadata.
- Revocation: Removed the five obsolete version records and their associated watermarked PDF files from live storage. Backup copies were retained privately.
- Verification: Confirmed the live PDF matches its database SHA-256, all five revoked version links return HTTP 404, /healthz returns HTTP 200 with database connectivity, and unauthenticated access to document 646 returns HTTP 401.
- Additional testing: Python syntax check passed; three dedicated metadata-watermark tests and fifteen shared watermark tests passed after correcting an invalid shared PDF fixture.
- Limitations: Authenticated owner retrieval has not been verified. The original vulnerability remains unknown, and previously downloaded copies cannot be revoked.
- Follow-up: Disclose the breach on the course forum, confirm the professor's secure procedure for registering the replacement flag, and continue investigating the root cause.
