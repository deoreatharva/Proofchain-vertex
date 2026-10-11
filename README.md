# ProofChain

> Cryptographic document integrity verification system built on Merkle tree proofs and ledger anchoring.

## Overview

ProofChain is a tamper-evident document registry that utilizes SHA-256 canonical fingerprinting, Merkle tree batching, Ed25519 checkpoint signing, and independent witness anchoring to provide client-side provable document integrity.

## Architecture

```
+---------------------------------------------------------+
|                  ProofChain Frontend                    |
+--------------+--------------+------------+--------------+
|  /register   |  /batches    |  /verify   |   /audit     |
|  Ingestion   |  Ledger      | Standalone |   Tamper     |
|  & Register  |  Status      | Verifier   |   Demo       |
+--------------+--------------+------------+--------------+
|              WebCrypto (crypto.subtle)                  |
|              SHA-256 | Merkle Trees | RFC 8785          |
+---------------------------------------------------------+
```

## Design System Constraints

- **Color Palette:** Grayscale only (`#000000` primary text/borders, `#FFFFFF` background, `#71717A` secondary text, `#F4F4F5` muted fill). No gradients, no accent colors.
- **Typography:** System Sans-Serif (Inter, system-ui, -apple-system) for labels; System Monospace (ui-monospace, Courier New) for hex digests, byte representations, and error codes.
- **Component Styling:** Flat 1px solid borders (border-neutral-900), zero box-shadows, rectangular containers (0px or 2px border radius).
- **Zero Decorative Indicators:** Pure computation outputs and protocol failure codes displayed directly.

---

## Core Views Overview

### 1. Registration & Ingestion View (`ui/register.html`)

Handles document ingestion, canonicalization, advisory AI metadata review, and fingerprint generation.

**Inputs and Controls:**
- **File Upload Area:** Accepts binary files (PDF, images) or structured JSON payloads.
- **Canonical Format Selector:**
  - `proofchain/v1/file`
  - `RFC 8785 (JSON Canonicalization Scheme)`
  - `UTF-8 NFC Plain Text`
- **AI Metadata Review Drawer:**
  - Model-extracted fields: `issuer`, `date`, `document_type`, `category`.
  - Required Header: `AI-Generated Advisory Metadata`.
  - Action Controls: Inline edit inputs and `Confirm Metadata` button (records `confirmed_by` and `confirmed_at`).
- **Output Container:**
  - Computed Fingerprint Box: Monospace read-only text displaying `SHA-256(tag || canonical_bytes)` (64 hex characters).
  - Status Badge: `PENDING_BATCH`.
  - Ingestion Action: Dynamically assigns document to active batch and exports proof bundle.

---

### 2. Batch & Ledger Status View (`ui/batches.html`)

Displays batched checkpoint records anchored to ledger witnesses.

**Batch Ledger Schema:**

| Field | Type / Format | Description |
| --- | --- | --- |
| `batch_id` | String (`YYYY-MM-BXXXX`) | Checkpoint batch identifier |
| `tree_size` | Integer | Total registered leaves in batch |
| `root` | 64 Hex Characters | Merkle root hash |
| `prev_checkpoint_hash` | 64 Hex Characters | Previous checkpoint hash in chain |
| `timestamp` | ISO-8601 UTC String | Checkpoint creation timestamp |
| `signature` | Ed25519 Hex / Base64 | Checkpoint signature |
| `state` | `PENDING` \| `SEALED` \| `ANCHORED` | Ledger lifecycle state |

**Batch Detail Drawer:**
- **Merkle Tree DAG:** Tree layout mapping Leaf Hashes (`0x00 || fingerprint`) to Interior Nodes (`0x01 || left || right`) up to root.
- **Export Action:** Generates and downloads standard proof bundle JSON for any selected leaf index.

---

### 3. Standalone Verifier View (`ui/verify.html`)

Operates entirely client-side via WebCrypto (`crypto.subtle`) without database or network connections.

**Input Form (3 Independent Dropzones / Inputs):**
1. **Document Input:** Raw file upload or plain text input.
2. **Proof Bundle Input:** JSON file drop or paste:
```json
{
  "version": "proofchain-proof/1",
  "canonicalization": "string",
  "fingerprint": "string (64 hex)",
  "leaf_index": 0,
  "tree_size": 0,
  "path": ["string (64 hex)"],
  "claimed_root": "string (64 hex)",
  "batch_id": "string"
}
```
3. **Published Root Input:** Text field for 64-hex root string or Checkpoint JSON.

**Step-by-Step Diagnostic Stepper:**

| Step | Protocol Check | Official Failure Code |
| --- | --- | --- |
| V0 | Input Well-Formedness Checks | `MALFORMED_INPUT` |
| V1 | Canonicalization Parser Checks | `UNSUPPORTED_FORMAT` |
| V2 | Raw File SHA-256 == Proof Fingerprint | `DOCUMENT_MODIFIED` |
| V3 | Leaf Index & Path Length Bounds | `INVALID_PROOF` |
| V4 | Recomputed Path == Claimed Root | `INVALID_PROOF` |
| V5 | Recomputed Root == Published Root | `ROOT_MISMATCH` |
| V6 | Checkpoint Ed25519 & Chain Validity | `CHECKPOINT_INVALID` |

**Verification Results Pane:**
- **Final Verdict Display:** Monospace heading displaying `VERDICT: VALID` or `VERDICT: FAILED`.
- **Failure Code List:** Ordered list of all failed codes (primary code first).
- **Hash Inspection Panel (Side-by-Side):**
  - Computed Document SHA-256
  - Claimed Proof Fingerprint
  - Recomputed Merkle Root
  - Published Reference Root
- **Advisory Explanation Box:**
  - Header: `System Advisory Note (Non-Authoritative)`

---

### 4. Audit & Tamper Demonstration View (`ui/audit.html`)

Evaluation and verification testing environment.

- **Side-by-Side Verification Comparison:**
  - **Column A (Naive Registry):** Internal database check (`document hash stored directly beside record`).
  - **Column B (ProofChain):** External ledger verification anchored to independent witnesses.
- **Tamper Simulation Buttons:**
  - **Corrupt 1 Byte in File:** Triggers `DOCUMENT_MODIFIED`.
  - **Corrupt Proof Sibling Hash:** Triggers `INVALID_PROOF`.
  - **Modify Database Record & Rebuild DB Root:** Demonstrates Naive system passing while ProofChain halts with `ROOT_MISMATCH`.
- **Subtree Mismatch Locator:**
  - Displays the exact node where local database hash diverged from published root via tree audit traversal.

---

## Project Structure

```
Proofchain-vertex/
├── index.html              # Entry forwarder redirecting to ui/index.html
├── ui/                     # Compiled UI application folder
│   ├── index.html          # Shell and navigation entry point
│   ├── register.html       # View 1: Ingestion & Registration
│   ├── batches.html        # View 2: Batch & Ledger Status
│   ├── verify.html         # View 3: Standalone Client-Side Verifier
│   ├── audit.html          # View 4: Audit & Tamper Demonstration
│   ├── css/
│   │   └── style.css       # Specification-compliant grayscale design system
│   └── js/
│       ├── crypto.js       # WebCrypto engine (SHA-256, Merkle DAG, RFC 8785)
│       ├── state.js        # Dynamic ledger storage and proof generator
│       ├── register.js     # View 1 controller
│       ├── batches.js      # View 2 controller
│       ├── verify.js       # View 3 controller
│       └── audit.js        # View 4 controller
└── README.md
```

## Running the Application

Open `index.html` or `ui/index.html` in any modern web browser:

```bash
open index.html
```

All cryptographic operations run directly in the client using the browser's native `crypto.subtle` API.
