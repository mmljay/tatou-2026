cat > artifacts/yomal-operational-security/code-changes/CHANGES.md << 'EOF'

\# Security changes — mapped to threat model IDs



\- TM-01/TM-02: delete\_document rewritten as single owner-scoped transaction,

&#x20; raises instead of early `return` to avoid partial commits.

\- TM-05: \_resolve\_under() added — confines file paths to the requesting

&#x20; user's own directory in create\_watermark, read\_watermark, delete\_document,

&#x20; get\_version. (get\_document still uses the broader \_safe\_resolve\_under\_storage()

&#x20; — documented as a residual gap, not yet fixed.)

\- TM-07: required\_secret() enforces 32-char minimum for SECRET\_KEY and

&#x20; RMAP\_WATERMARK\_KEY before the app will start.

\- TM-09: legacy 40-char SHA-1 links explicitly rejected via recomputation check.

\- Observation points: log\_access\_denied() added at all 5 ownership-check

&#x20; call sites (get\_document, delete\_document, create\_watermark,

&#x20; read\_watermark\_document, read\_watermark\_version), writing to

&#x20; storage/security.log (0600 permissions).

EOF

