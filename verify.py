#!/usr/bin/env python3
"""ProofChain standalone verifier. Standard library only; never touches the registry database.

Usage:
  python verify.py --doc cert.txt --proof cert.proof.json --log published/roots.log [--log2 mirror/roots.log] [--anchor HEAD_HASH]
  python verify.py --doc cert.txt --proof cert.proof.json --root <64-hex published root>
Exit code 0 = VERIFIED, 1 = rejected (the failing check is printed).
"""
import argparse, hashlib, json, os, re, sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TEXT_EXT = {".txt", ".md", ".csv", ".json", ".xml", ".html"}
GENESIS = "0" * 64
STEPS = ["proof_format", "document_hash", "proof_path", "log_integrity", "root_published"]
EXPLAIN = {
    "VERIFIED": "The document matches the registered reference. This does not prove who created it or that its contents are true.",
    "PROOF_INVALID": "The proof file is malformed, its path does not fold to the claimed root, or the path length is inconsistent with tree_size/leaf_index.",
    "DOC_MODIFIED": "The document's fingerprint differs from the one registered. The file was changed after registration.",
    "ROOT_MISMATCH": "The proof is internally consistent, but its root differs from the published root. The registry copy was altered, or this proof is forged.",
    "ROOT_NOT_PUBLISHED": "No published root could be found for this batch, so the record cannot be confirmed.",
    "LOG_TAMPERED": "The published-roots log fails its own integrity check, or the primary and mirror logs disagree — the log was edited, truncated, or one copy was altered.",
}


def canonicalize(data: bytes, filename: str = "") -> bytes:
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if ext in TEXT_EXT:
        try:
            s = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        return ("\n".join(l.rstrip() for l in s.split("\n")).strip("\n") + "\n").encode()
    return data


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fold(doc_hash: str, leaf_index: int, tree_size: int, path: list) -> str:
    """RFC 9162 §2.1.3.2 inclusion-proof fold.
    Derives direction at each step from leaf_index and tree_size — no stored pos flags needed.
    Returns '' if the path length is inconsistent with tree_size/leaf_index (implicit length check:
    fn and sn must both reach 0 after consuming all path elements)."""
    fn = leaf_index
    sn = tree_size - 1
    r = hashlib.sha256(b"\x00" + bytes.fromhex(doc_hash)).digest()
    for p_hex in path:
        if fn == 0 and sn == 0:
            return ""   # path has extra siblings after already reaching the root
        p = bytes.fromhex(p_hex)
        if fn == sn or (fn & 1):
            r = hashlib.sha256(b"\x01" + p + r).digest()   # sibling on the left
            while (fn > 0) and not (fn & 1):                # skip promoted (no-sibling) levels
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()   # sibling on the right
        fn >>= 1
        sn >>= 1
    if fn != 0 or sn != 0:
        return ""   # path too short or too long for this tree_size/leaf_index
    return r.hex()


def format_error(p):
    if not isinstance(p, dict):
        return "proof is not a JSON object"
    for k in ("batch_id", "doc_hash", "leaf_index", "tree_size", "path", "root"):
        if k not in p:
            return f"missing field '{k}'"
    if not HEX64.match(str(p["doc_hash"])) or not HEX64.match(str(p["root"])):
        return "doc_hash/root must be 64 lowercase hex characters"
    if not isinstance(p["leaf_index"], int) or p["leaf_index"] < 0:
        return "leaf_index must be a non-negative integer"
    if not isinstance(p["tree_size"], int) or p["tree_size"] < 1:
        return "tree_size must be a positive integer"
    if p["leaf_index"] >= p["tree_size"]:
        return f"leaf_index {p['leaf_index']} out of range for tree_size {p['tree_size']}"
    if not isinstance(p["path"], list):
        return "path must be a list"
    for s in p["path"]:
        if not (isinstance(s, str) and HEX64.match(s)):
            return "each path step must be a 64-char lowercase hex string"
    return None


def check_log(log_path, anchor=None):
    """Returns (ok, detail, entries). Recomputes every entry hash and the prev-links."""
    try:
        lines = open(log_path).read().splitlines()
    except OSError:
        return False, "roots log not found", []
    entries, prev = [], GENESIS
    for i, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
            body = {k: e[k] for k in ("seq", "batch_id", "root", "count", "ts", "prev")}
            ok = e["seq"] == i and e["prev"] == prev and e["entry_hash"] == sha(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        except Exception:
            ok = False
        if not ok:
            return False, f"entry {i} breaks the hash chain", entries
        entries.append(e)
        prev = e["entry_hash"]
    if anchor and anchor not in {e["entry_hash"] for e in entries}:
        return False, "anchor hash not found in log (log was rewritten or truncated)", entries
    return True, f"{len(entries)} entries, chain intact", entries


def check_logs_agree(log1_path, log2_path):
    """Returns (ok, detail). Verifies two independently-kept log copies are identical.
    Either log failing its own integrity check also fails here."""
    ok1, det1, entries1 = check_log(log1_path)
    ok2, det2, entries2 = check_log(log2_path)
    if not ok1:
        return False, f"primary log invalid: {det1}"
    if not ok2:
        return False, f"mirror log invalid: {det2}"
    if len(entries1) != len(entries2):
        return False, f"logs have different lengths ({len(entries1)} vs {len(entries2)}) — one may be truncated or ahead"
    for i, (e1, e2) in enumerate(zip(entries1, entries2), 1):
        if e1["entry_hash"] != e2["entry_hash"]:
            return False, f"logs diverge at entry {i} — one copy was edited after mirroring"
    return True, f"{len(entries1)} entries, both logs agree"


def verify(doc_bytes, filename, proof, published_root=None, log_path=None, anchor=None, log_path2=None):
    res = {"ok": False, "code": None, "message": "", "checks": []}

    def step(name, ok, detail):
        res["checks"].append({"name": name, "status": "pass" if ok else "fail", "detail": detail})
        return ok

    def stop(code):
        done = {c["name"] for c in res["checks"]}
        res["checks"] += [{"name": n, "status": "skip", "detail": "not reached"} for n in STEPS if n not in done]
        res["checks"].sort(key=lambda c: STEPS.index(c["name"]))
        res.update(code=code, message=EXPLAIN[code], ok=code == "VERIFIED")
        return res

    err = format_error(proof)
    if not step("proof_format", err is None, err or "well-formed"):
        return stop("PROOF_INVALID")

    dh = sha(canonicalize(doc_bytes, filename))
    if not step("document_hash", dh == proof["doc_hash"],
                f"document SHA-256 {dh[:16]}... vs registered {proof['doc_hash'][:16]}..."):
        return stop("DOC_MODIFIED")

    computed = fold(proof["doc_hash"], proof["leaf_index"], proof["tree_size"], proof["path"])
    if computed:
        path_ok = computed == proof["root"]
        path_detail = f"path folds to {computed[:16]}... {'(matches root)' if path_ok else 'vs proof root ' + proof['root'][:16] + '...'}"
    else:
        path_ok = False
        path_detail = "path length is inconsistent with tree_size/leaf_index"
    if not step("proof_path", path_ok, path_detail):
        return stop("PROOF_INVALID")

    pub = published_root
    if log_path:
        ok_log, detail_log, entries = check_log(log_path, anchor)
        # If primary is valid AND a mirror exists, check both agree
        if ok_log and log_path2 and os.path.exists(log_path2):
            combined_ok, combined_detail = check_logs_agree(log_path, log_path2)
        else:
            combined_ok, combined_detail = ok_log, detail_log
        if not step("log_integrity", combined_ok, combined_detail):
            return stop("LOG_TAMPERED")
        if not pub:
            m = [e["root"] for e in entries if e["batch_id"] == proof["batch_id"]]
            pub = m[-1] if m else None

    if not pub:
        step("root_published", False, f"no published root for batch {proof['batch_id']}")
        return stop("ROOT_NOT_PUBLISHED")
    if not step("root_published", computed == pub,
                f"computed {computed[:16]}... vs published {pub[:16]}..."):
        return stop("ROOT_MISMATCH")
    return stop("VERIFIED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--doc", required=True)
    ap.add_argument("--proof", required=True)
    ap.add_argument("--root")
    ap.add_argument("--log")
    ap.add_argument("--log2", help="Mirror log path; verifier checks that both logs agree")
    ap.add_argument("--anchor")
    a = ap.parse_args()
    try:
        proof = json.load(open(a.proof))
    except Exception:
        proof = None
    r = verify(open(a.doc, "rb").read(), a.doc, proof, a.root, a.log, a.anchor, a.log2)
    for c in r["checks"]:
        print(f"[{c['status'].upper():4}] {c['name']:15} {c['detail']}")
    print(f"\n{r['code']}: {r['message']}")
    sys.exit(0 if r["ok"] else 1)
