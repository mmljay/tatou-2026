cat > artifacts/yomal-operational-security/logs/evidence-queries.sql << 'EOF'
-- Confirm document-3 (RMAP source doc) ownership
SELECT id, name, ownerid FROM Documents WHERE id = 3;
SELECT id, login, email FROM Users WHERE id = (SELECT ownerid FROM Documents WHERE id = 3);

-- Adversarial account discovery
SELECT login, email FROM Users WHERE id != 3 ORDER BY id;

-- evil.pkl / pwn_* cluster (TM-10 probing)
SELECT d.id, d.name, d.ownerid, u.login
FROM Documents d JOIN Users u ON d.ownerid = u.id
WHERE u.login LIKE 'pwn_%';

-- Mr_Important / flag_3 traversal case study
SELECT id, name, ownerid FROM Documents WHERE name LIKE '%Mr_Important%'
   OR ownerid IN (SELECT id FROM Users WHERE login = 'Mr_Important');
SELECT id, name, ownerid FROM Documents WHERE id = 646;
SELECT v.id, v.link, v.intended_for FROM Versions v WHERE v.documentid = 646;

-- RMAP document-3 request history
SELECT id, documentid, intended_for, method, link
FROM Versions WHERE documentid = 3 ORDER BY id DESC;
EOF