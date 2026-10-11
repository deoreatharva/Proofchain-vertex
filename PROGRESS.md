# PROGRESS (handoff file for any AI or teammate)

Project: ProofChain (Vortexa 3.0, problem B-01). Built from scratch at the event; no code reused from the SIH 26 repo.
Stack: FastAPI + SQLite + one static HTML page + standalone `verify.py` (standard library only). No external service needed for the core demo.
Run: `pip install -r requirements.txt` then `uvicorn app:app --reload` (http://127.0.0.1:8000). Tests: `python -m pytest -q` (needs pytest, httpx).

## Done (working and tested: 28 tests passing, UI confirmed working by the team)
- Canonical form + SHA-256 fingerprint (proofchain/core.py). Text files normalized, binary files hashed as raw bytes.
- Merkle tree: leaf = SHA256(0x00||doc_hash), node = SHA256(0x01||left||right), odd node promoted. Root matches RFC 6962 / RFC 9162.
- Hardened Merkle proof (RFC 9162): proof includes tree_size, leaf_index, and list of sibling hashes. Direction derived dynamically using bit shifts; implicit path-length consistency verified.
- Dual append-only roots log with independent mirror: primary in published/roots.log and mirror in mirror/roots.log. Verifier checks both and flags disagreement.
- Standalone CLI verifier verify.py (stdlib only): supports --log, --log2, --anchor, --root. Error codes: PROOF_INVALID, DOC_MODIFIED, ROOT_MISMATCH, ROOT_NOT_PUBLISHED, LOG_TAMPERED.
- Zero-trust browser verifier (static/verify.html & /verify): 100% offline client-side verification using W3C WebCrypto API.
- Architecture comparison panel: side-by-side comparison proving that a naive hash-in-DB architecture is fooled by custodian database rewrites, while ProofChain detects the tampering.
- Registry audit (stored file vs DB hash, DB root rebuilt, DB root vs published root, dual-log consensus).
- AI metadata suggestion (issuer, date, type) with local rules fallback. Human confirms every field. AI never touches verification.
- Role-based portal & human audit stamp (/login): Registrar (Officer Aarav) & Auditor (Inspector Maya) with 1-click demo logins; confirmed_by and confirmed_at recorded for every registered record.
- UI tabs: Register, Registry, Verify, Audit and demo (dual-log status, naive comparison, attack, tamper, reset).
- README.md has the design, limits and a 90-second demo script.

## Tier A & Tier B Progress Completed (11 Oct)
1. Independent mirror roots log (published/roots.log and mirror/roots.log), dual-log agreement check, anchor hash display.
2. Hardened proof with tree_size & leaf_index, RFC 9162 inclusion folding, implicit length check.
3. Single-page zero-trust browser verifier via WebCrypto (static/verify.html).
4. Naive vs ProofChain side-by-side comparison panel in the UI.
5. Role-based login portal (/login) and human confirmation tracking (confirmed_by / confirmed_at audit stamps).

## 3-Party Consent Workflow (done, tested: 47 tests passing, flow also driven end to end in a real browser)
- Roles: registrar/admin (issue), candidate (owns credentials, approves access), verifier (requests access, verifies), auditor (read-only oversight). Hardcoded demo accounts only.
- `records.candidate_name` (default "Aarav Kulkarni", added by ALTER TABLE on old databases) + `access_requests` table (pending/approved/rejected).
- Endpoints: `POST /api/access/request`, `GET /api/access/requests`, `POST /api/access/respond/{id}` (approve | reject; reject on an approved request = revoke), `GET /api/candidate/documents`, `GET /api/candidates`; `POST /api/register` takes `candidate_name`.
- Privacy gatekeeper on `/api/file/{id}`, `/api/proof/{id}`, `/api/verify-record/{id}`. `/api/records` is role-aware (verifiers get a directory without fingerprints).
- Register/publish/extract are registrar/admin only. Audit, naive-verify and demo endpoints are registrar/admin/auditor only. `/api/log` and `/api/verify` stay public.
- Login fixed: a password is now always required (an empty password used to be accepted); `/api/auth/me` no longer returns passwords.
- Existing test `test_api_full_flow_and_db_rewrite_attack` now signs in as registrar first (guests can no longer download files). Its crypto assertions are unchanged.
- UI: role-based tabs, "Switch Role" button, candidate vault + inbox (pending badge), verifier directory + approved list + one-click verify.

## Planned next
6. Stronger tests: random batch sizes, flip any single bit (document, path, root) must fail, verifier with registry deleted and no network.
7. Demo-mode flag for the attack, tamper and reset endpoints.
8. Version tag in the fingerprint and a short written canonicalization spec.
Skip: signed checkpoints, RFC 3161, witnesses, salts, revocation (list as future work).

## Demo script (90 seconds)
Load 5 samples > check stored copy (Verified) > change one character of a downloaded doc (DOC_MODIFIED) > "Edit document and rewrite database" then check stored copy (ROOT_MISMATCH) > "Edit the roots log" (LOG_TAMPERED). Press Reset between rehearsals.

## Must be able to explain without notes
Why the database alone proves nothing; why the roots log sits outside the registry; what a Merkle proof lets the verifier do; what the system does NOT prove (authorship, truth of contents).
