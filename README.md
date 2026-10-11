# ProofChain: Verifiable Records & Tamper Detection (Vortexa 3.0, B-01)

Registers documents, groups them into batches under a Merkle root, publishes each root to dual append-only,
hash-chained logs kept **outside** the registry, and lets an independent verifier check one document using only
the document, its proof and the published root.

## Run
    pip install -r requirements.txt
    uvicorn app:app --reload          # open http://127.0.0.1:8000
    python -m pytest -q               # 47 tests passing

## Design
- **Fingerprint:** SHA-256 of a canonical form. Binary files = raw bytes. Text files (.txt .md .csv .json .xml .html) = UTF-8 without BOM,
  `\n` line endings, trailing spaces removed, outer blank lines trimmed, one final newline.
- **Merkle tree:** leaf = `SHA256(0x00 || doc_hash)`, node = `SHA256(0x01 || left || right)`. Domain prefixes block second-preimage attacks.
  An odd node is promoted unchanged (never duplicated).
- **Hardened Proof (RFC 9162):** JSON contains `batch_id`, `doc_hash`, `leaf_index`, `tree_size`, sibling hashes list, and `root`.
  Directions are dynamically derived at verification time using `leaf_index` and `tree_size` bit shifts. Path length consistency is verified implicitly.
- **Dual Published Roots Logs:** `published/roots.log` and independent `mirror/roots.log`, one JSON line per batch, each committing to the previous line's hash.
  Verifier checks internal chain integrity of both logs and alerts if they diverge. Anchor hash displayed in UI guards against truncation attacks.
- **3-Party Consent Workflow (`/login`):** Registrar (issuer) -> Candidate (credential owner) -> Verifier (third party), with 1-click demo logins.
  1. The **Registrar** registers a document and assigns it to a **Candidate**, then publishes the batch. Every record commits a human audit stamp (`confirmed_by`, `confirmed_at`) taken from the signed-in registrar.
  2. The **Candidate** has a *My Document Vault* (everything issued in their name, and who it is shared with) and an *Access Requests* inbox.
  3. A **Verifier** can browse a directory (no fingerprints) but cannot open any document or proof. They send an **access request**.
  4. The Candidate clicks **Approve Access** or **Decline** (an approved request can be **revoked** later; a declined one is final, the verifier must ask again).
  5. Once approved, the Verifier unlocks the document and `.proof.json` and clicks **Verify Cryptographically** (server `/api/verify`, or the offline `/verify` page).
  - Gatekeeper on `/api/file/{id}`, `/api/proof/{id}` and `/api/verify-record/{id}`: registrar/admin, or the record's candidate, or a verifier with an *approved* request. Everyone else gets 401/403. The auditor sees registry metadata and audits but not contents.
  - Identities are taken from the login session and from the record, never from request fields, so a verifier cannot pretend to be another verifier or candidate.
  - Demo accounts (hardcoded, **demo only**): `Atharva`/`1234` (Chief Registrar), `candidate`/`1234` (Aarav Kulkarni), `verifier`/`1234` (TechCorp HR); also `registrar`/`password123`, `auditor`/`password123`, `meera`/`1234` (second candidate), `recruiter`/`1234` (second verifier), `admin`/`admin`.
  - Consent controls access to documents; it does not change the cryptography. `core.py`, `verify.py` and the Merkle/RFC 9162 logic are untouched.
- **Independent Verifier:** `verify.py` uses the standard library only and never opens the registry DB.
      python verify.py --doc a.txt --proof a.txt.proof.json --log published/roots.log [--log2 mirror/roots.log] [--anchor HEAD]
      python verify.py --doc a.txt --proof a.txt.proof.json --root <64-hex>
  Failure codes: `PROOF_INVALID`, `DOC_MODIFIED`, `ROOT_MISMATCH`, `ROOT_NOT_PUBLISHED`, `LOG_TAMPERED`.
- **Zero-Trust Browser Verifier (`/verify`):** 100% client-side verification using the W3C WebCrypto API. Operates entirely offline with zero server calls.
- **Architecture Comparison Panel:** Direct side-by-side test showing how naive systems (hashes stored in DB) pass blindly when an insider rewrites both document and database, while ProofChain rejects the tamper with `ROOT_MISMATCH`.
- **Registry Audit:** Recomputes every stored file's hash, rebuilds every root from DB, checks DB root vs published root, and validates dual-log agreement.
- **AI (optional):** Suggests issuer, date, and document type. Falls back to local regex rules when no API key is present. A human must confirm every field; AI never touches verification.

## Demo (about 2 minutes, three roles)
1. Sign in as **Chief Registrar (Atharva)** > **Audit and demo** > *Load 5 sample certificates* (each is issued to the person named inside it; certificate_1 belongs to Aarav Kulkarni). Optionally **Register** another document for Aarav and publish it.
2. **Switch Role** > **Candidate (Aarav Kulkarni)**: *My Document Vault* shows only Aarav's credentials.
3. **Switch Role** > **Verifier (TechCorp HR)**: *Request Document Access* > **Request access** on Aarav's certificate. Opening it is refused (403) and *Approved Documents* is empty.
4. **Switch Role** > **Candidate**: *Access Requests (1)* > **Approve Access**.
5. **Switch Role** > **Verifier**: *Approved Documents to Verify* > **Verify Cryptographically**: **Verified**.
6. Back as the Candidate, **Revoke access**: the verifier is locked out again.
7. Tamper demo (as Registrar): click **Edit document and rewrite database**, then **Compare Architectures**: naive DB check **FOOLED**, ProofChain **CAUGHT: ROOT_MISMATCH**. **Edit the roots log** gives **LOG_TAMPERED**.
8. Open the **Zero-Trust WebCrypto Verifier** (`/verify`) to verify a document and proof 100% offline.

## Honest limits
Verification proves a document matches a registered reference. It does not prove who created it or that its contents are true.
No public blockchain is required; the dual append-only logs stand in for external immutable storage.
