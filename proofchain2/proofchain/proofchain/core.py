"""Registry-side crypto: canonical form, SHA-256 fingerprints, Merkle tree, roots log writer."""
import hashlib, json, time
from pathlib import Path

TEXT_EXT = {".txt", ".md", ".csv", ".json", ".xml", ".html"}
GENESIS = "0" * 64


def canonicalize(data: bytes, filename: str = "") -> bytes:
    """Defined, reproducible form. Binary files: raw bytes. Text files: UTF-8 (BOM removed),
    \\n line endings, trailing spaces stripped per line, outer blank lines trimmed, one final \\n."""
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if ext in TEXT_EXT:
        try:
            s = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        return ("\n".join(l.rstrip() for l in s.split("\n")).strip("\n") + "\n").encode()
    return data


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leaf_hash(doc_hash_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(doc_hash_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def build_tree(doc_hashes_hex):
    """Returns levels (list of lists of bytes). An odd node is promoted unchanged (no duplication)."""
    if not doc_hashes_hex:
        raise ValueError("empty batch")
    levels = [[leaf_hash(h) for h in doc_hashes_hex]]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(node_hash(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i])
        levels.append(nxt)
    return levels


def root_hex(levels) -> str:
    return levels[-1][0].hex()


def proof_path(levels, index: int):
    """Returns list of sibling hex strings (no pos flags).
    Direction is derived from leaf_index + tree_size at verification time (RFC 9162)."""
    path, idx = [], index
    for level in levels[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                path.append(level[idx + 1].hex())
        else:
            path.append(level[idx - 1].hex())
        idx //= 2
    return path


def make_proof(levels, index, batch_id, name, doc_hash):
    tree_size = len(levels[0])          # number of leaves in this batch
    return {"version": 1, "batch_id": batch_id, "doc_name": name, "doc_hash": doc_hash,
            "leaf_index": index, "tree_size": tree_size,
            "path": proof_path(levels, index), "root": root_hex(levels)}


def _entry_hash(body: dict) -> str:
    return sha256_hex(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def log_append(log_path: Path, batch_id: str, root: str, count: int) -> dict:
    """Append-only, hash-chained roots log. Each entry commits to the previous one.
    Returns the entry dict so callers can mirror it verbatim to additional locations."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines = log_path.read_text().splitlines() if log_path.exists() else []
    last = json.loads(lines[-1]) if lines else None
    body = {"seq": len(lines) + 1, "batch_id": batch_id, "root": root, "count": count,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "prev": last["entry_hash"] if last else GENESIS}
    entry = {**body, "entry_hash": _entry_hash(body)}
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def log_mirror(entry: dict, log_path: Path) -> None:
    """Write an already-computed log entry verbatim to a mirror path.
    Both logs will have identical content (same seq, prev, ts, entry_hash)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
