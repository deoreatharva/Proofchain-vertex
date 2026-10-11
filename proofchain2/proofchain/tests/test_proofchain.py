import json, os, subprocess, sys, tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp()
os.environ["PROOFCHAIN_DATA"]      = f"{_tmp}/data"
os.environ["PROOFCHAIN_PUBLISHED"] = f"{_tmp}/published"
os.environ["PROOFCHAIN_MIRROR"]    = f"{_tmp}/mirror"
os.environ.pop("ANTHROPIC_API_KEY", None)
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
import verify
from proofchain import core
import app as appmod

client = TestClient(appmod.app)


def docs(n):
    return [(f"doc{i}.txt", f"document number {i}\n".encode()) for i in range(n)]


@pytest.mark.parametrize("n", range(1, 18))
def test_every_leaf_verifies_for_any_batch_size(n):
    d = docs(n)
    hashes = [core.sha256_hex(core.canonicalize(b, nm)) for nm, b in d]
    levels = core.build_tree(hashes)
    for i, (nm, b) in enumerate(d):
        p = core.make_proof(levels, i, "B1", nm, hashes[i])
        assert verify.verify(b, nm, p, published_root=core.root_hex(levels))["code"] == "VERIFIED"


def _setup(n=5):
    d = docs(n)
    hashes = [core.sha256_hex(core.canonicalize(b, nm)) for nm, b in d]
    levels = core.build_tree(hashes)
    return d, hashes, levels, core.root_hex(levels)


def test_modified_document():
    d, h, lv, root = _setup()
    p = core.make_proof(lv, 2, "B1", d[2][0], h[2])
    assert verify.verify(d[2][1] + b"x", d[2][0], p, root)["code"] == "DOC_MODIFIED"


def test_invalid_proof_wrong_sibling_and_malformed():
    d, h, lv, root = _setup()
    p = core.make_proof(lv, 2, "B1", d[2][0], h[2])
    # path is now a list of hex strings; corrupt first sibling
    p["path"][0] = "ab" * 32
    assert verify.verify(d[2][1], d[2][0], p, root)["code"] == "PROOF_INVALID"
    # leaf_index out of range
    p2 = core.make_proof(lv, 2, "B1", d[2][0], h[2])
    p2["leaf_index"] = 99
    assert verify.verify(d[2][1], d[2][0], p2, root)["code"] == "PROOF_INVALID"
    # missing fields
    assert verify.verify(d[2][1], d[2][0], {"nope": 1}, root)["code"] == "PROOF_INVALID"
    assert verify.verify(d[2][1], d[2][0], None, root)["code"] == "PROOF_INVALID"


def test_root_mismatch_and_not_published():
    d, h, lv, root = _setup()
    p = core.make_proof(lv, 0, "B1", d[0][0], h[0])
    assert verify.verify(d[0][1], d[0][0], p, "cd" * 32)["code"] == "ROOT_MISMATCH"
    assert verify.verify(d[0][1], d[0][0], p)["code"] == "ROOT_NOT_PUBLISHED"


def test_whitespace_canonicalisation_is_stable_but_content_change_is_not():
    a = b"Hello  \r\nWorld\r\n\r\n"
    b = b"Hello\nWorld\n"
    assert core.canonicalize(a, "x.txt") == core.canonicalize(b, "x.txt") == verify.canonicalize(a, "x.txt")
    assert core.canonicalize(b"\x00\x01 \r\n", "x.pdf") == b"\x00\x01 \r\n"  # binary untouched


def test_log_chain_and_tamper_detection(tmp_path):
    log    = tmp_path / "roots.log"
    mirror = tmp_path / "mirror.log"

    e1 = core.log_append(log, "B0001", "aa" * 32, 3)
    core.log_mirror(e1, mirror)
    e2 = core.log_append(log, "B0002", "bb" * 32, 4)
    core.log_mirror(e2, mirror)

    assert verify.check_log(log)[0]
    assert verify.check_log(log, anchor=e2["entry_hash"])[0]
    assert verify.check_logs_agree(log, mirror)[0], "identical logs must agree"

    # Tamper primary log
    lines = log.read_text().splitlines()
    first = json.loads(lines[0]); first["root"] = "cc" * 32; lines[0] = json.dumps(first, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    assert not verify.check_log(log)[0]
    assert not verify.check_logs_agree(log, mirror)[0], "tampered primary must fail agreement"

    # Truncation / replacement (anchor detects log rewrite even if truncated chain is valid)
    log.write_text(json.dumps(json.loads(lines[1])) + "\n")
    assert not verify.check_log(log, anchor=e2["entry_hash"])[0]


def test_api_full_flow_and_db_rewrite_attack():
    # Documents/proofs are now behind the consent gatekeeper, so this flow runs as the registrar.
    # A fresh client keeps its cookie separate from the module-level guest client used by the auth test.
    client = TestClient(appmod.app)
    assert client.post("/api/auth/login", data={"username": "registrar", "password": "password123"}).status_code == 200
    client.post("/api/demo/reset")
    r = client.post("/api/demo/seed").json()
    assert r["count"] == 5 and client.post("/api/audit").json()["ok"]
    recs = client.get("/api/records").json()
    assert recs[0]["issuer"] == "Orion Institute of Technology" and recs[0]["doc_date"] == "2026-03-14"

    doc   = client.get("/api/file/1").content
    proof = client.get("/api/proof/1").content
    ok = client.post("/api/verify", files={"doc": ("certificate_1.txt", doc), "proof": ("p.json", proof)}).json()
    assert ok["code"] == "VERIFIED"
    bad = client.post("/api/verify", files={"doc": ("certificate_1.txt", doc + b"!"), "proof": ("p.json", proof)}).json()
    assert bad["code"] == "DOC_MODIFIED"

    # Naive verify before attack: PASS (expected)
    nv_before = client.post("/api/naive-verify/1").json()
    assert nv_before["naive_ok"] is True

    client.post("/api/demo/attack/1")                                  # edit doc + rewrite whole DB
    doc2, proof2 = client.get("/api/file/1").content, client.get("/api/proof/1").content
    assert doc2 != doc
    att = client.post("/api/verify", files={"doc": ("certificate_1.txt", doc2), "proof": ("p.json", proof2)}).json()
    assert att["code"] == "ROOT_MISMATCH"                              # ProofChain still rejects
    assert client.post("/api/verify-record/1").json()["code"] == "ROOT_MISMATCH"

    # Naive verify after attack: PASS (fooled — DB and file were both rewritten)
    nv_after = client.post("/api/naive-verify/1").json()
    assert nv_after["naive_ok"] is True, "naive check must be fooled by the DB-rewrite attack"

    codes = {f["code"] for f in client.post("/api/audit").json()["findings"]}
    assert "ROOT_MISMATCH" in codes

    client.post("/api/demo/tamper-log")
    assert client.post("/api/verify", files={"doc": ("c.txt", doc), "proof": ("p.json", proof)}).json()["code"] == "LOG_TAMPERED"


def test_cli_exit_codes(tmp_path):
    d, h, lv, root = _setup(3)
    (tmp_path / "a.txt").write_bytes(d[0][1])
    (tmp_path / "a.proof.json").write_text(json.dumps(core.make_proof(lv, 0, "B1", "a.txt", h[0])))
    run = lambda *x: subprocess.run([sys.executable, "verify.py", *x], capture_output=True, text=True,
                                    cwd=Path(__file__).parent.parent)
    assert run("--doc", str(tmp_path / "a.txt"), "--proof", str(tmp_path / "a.proof.json"), "--root", root).returncode == 0
    (tmp_path / "a.txt").write_bytes(b"tampered")
    r = run("--doc", str(tmp_path / "a.txt"), "--proof", str(tmp_path / "a.proof.json"), "--root", root)
    assert r.returncode == 1 and "DOC_MODIFIED" in r.stdout


def test_rfc9162_path_length_mismatch():
    d, h, lv, root = _setup(4)
    # Extra sibling in path
    p_long = core.make_proof(lv, 0, "B1", d[0][0], h[0])
    p_long["path"].append("11" * 32)
    assert verify.verify(d[0][1], d[0][0], p_long, root)["code"] == "PROOF_INVALID"

    # Truncated path (missing sibling)
    p_short = core.make_proof(lv, 0, "B1", d[0][0], h[0])
    p_short["path"].pop()
    assert verify.verify(d[0][1], d[0][0], p_short, root)["code"] == "PROOF_INVALID"


def test_dual_log_mirror_and_disagreement_detection(tmp_path):
    log1 = tmp_path / "primary.log"
    log2 = tmp_path / "mirror.log"
    e1 = core.log_append(log1, "B0001", "11" * 32, 2)
    core.log_mirror(e1, log2)
    e2 = core.log_append(log1, "B0002", "22" * 32, 3)
    core.log_mirror(e2, log2)

    ok, detail = verify.check_logs_agree(log1, log2)
    assert ok is True and "both logs agree" in detail

    # Truncate mirror log by one entry
    lines = log2.read_text().splitlines()
    log2.write_text(lines[0] + "\n")
    ok, detail = verify.check_logs_agree(log1, log2)
    assert ok is False and "different lengths" in detail

    # Tamper content of second entry in mirror log
    e2_bad = dict(e2)
    e2_bad["root"] = "99" * 32
    log2.write_text(lines[0] + "\n" + json.dumps(e2_bad, sort_keys=True) + "\n")
    ok, detail = verify.check_logs_agree(log1, log2)
    assert ok is False


def test_browser_verify_page_is_served():
    res = client.get("/verify")
    assert res.status_code == 200
    assert "Zero-Trust Browser Verifier" in res.text
    assert "foldRFC9162" in res.text


def test_login_page_and_auth_flow():
    # Login page is served
    res = client.get("/login")
    assert res.status_code == 200
    assert "Staff Sign In" in res.text
    assert "Officer Aarav" in res.text

    # Default is guest
    me = client.get("/api/auth/me").json()
    assert me["role"] == "public"

    # Invalid login fails
    bad = client.post("/api/auth/login", data={"username": "registrar", "password": "wrongpassword"})
    assert bad.status_code == 401

    # Valid registrar login succeeds and returns cookie
    login_res = client.post("/api/auth/login", data={"username": "registrar", "password": "password123"})
    assert login_res.status_code == 200
    user_data = login_res.json()["user"]
    assert user_data["role"] == "registrar"
    assert "Officer Aarav" in user_data["display_name"]

    # Verify session persists
    me2 = client.get("/api/auth/me").json()
    assert me2["role"] == "registrar"

    # Register document with registrar stamp
    reg = client.post("/api/register", files={"file": ("diploma.txt", b"Student Awarded Degree\n")},
                      data={"issuer": "National Tech University", "doc_date": "2026-05-20", "doc_type": "degree"})
    assert reg.status_code == 200
    reg_json = reg.json()
    assert "Officer Aarav" in reg_json["confirmed_by"]
    assert reg_json["confirmed_at"] is not None

    # Check record in registry
    recs = client.get("/api/records").json()
    target = next(r for r in recs if r["id"] == reg_json["id"])
    assert "Officer Aarav" in target["confirmed_by"]
    assert target["confirmed_at"] is not None

    # Logout
    client.post("/api/auth/logout")
    me3 = client.get("/api/auth/me").json()
    assert me3["role"] == "public"


