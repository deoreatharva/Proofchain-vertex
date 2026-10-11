"""3-party consent workflow: Registrar issues -> Candidate owns & approves -> Verifier requests, unlocks, verifies."""
import os, sqlite3, sys, tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp()
os.environ.setdefault("PROOFCHAIN_DATA",      f"{_tmp}/data")
os.environ.setdefault("PROOFCHAIN_PUBLISHED", f"{_tmp}/published")
os.environ.setdefault("PROOFCHAIN_MIRROR",    f"{_tmp}/mirror")
os.environ.pop("ANTHROPIC_API_KEY", None)
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
import app as appmod

CREDS = {
    "registrar": ("Atharva", "1234"),
    "candidate": ("candidate", "1234"),       # Aarav Kulkarni
    "meera":     ("meera", "1234"),           # Meera Joshi (second candidate)
    "verifier":  ("verifier", "1234"),        # TechCorp HR
    "recruiter": ("recruiter", "1234"),       # Orbit Recruiters (second verifier)
    "auditor":   ("auditor", "password123"),
}


def login(role):
    c = TestClient(appmod.app)                 # own cookie jar per actor
    u, p = CREDS[role]
    assert c.post("/api/auth/login", data={"username": u, "password": p}).status_code == 200
    return c


@pytest.fixture()
def world():
    """Fresh registry: sample certificates seeded + published. certificate_1 (id 1) is Aarav's, certificate_2 (id 2) is Meera's."""
    reg = login("registrar")
    reg.post("/api/demo/reset")
    assert reg.post("/api/demo/seed").status_code == 200
    return reg


# ---------- login ----------
@pytest.mark.parametrize("role", list(CREDS))
def test_demo_logins_work_and_do_not_leak_passwords(role):
    c = login(role)
    me = c.get("/api/auth/me").json()
    assert "password" not in me and "passwords" not in me
    assert me["role"] in ("registrar", "candidate", "verifier", "auditor")


def test_login_requires_the_right_password():
    c = TestClient(appmod.app)
    for u in ("registrar", "Atharva", "candidate", "verifier", "auditor", "admin"):
        assert c.post("/api/auth/login", data={"username": u, "password": ""}).status_code == 401, u
        assert c.post("/api/auth/login", data={"username": u}).status_code == 401, u
        assert c.post("/api/auth/login", data={"username": u, "password": "nope"}).status_code == 401, u
    assert c.post("/api/auth/login", data={"username": "nobody", "password": "1234"}).status_code == 401
    ok = c.post("/api/auth/login", data={"username": "Atharva", "password": "1234"}).json()["user"]
    assert ok["display_name"] == "Chief Registrar Atharva" and ok["role"] == "registrar" and "password" not in ok
    assert login("candidate").get("/api/auth/me").json()["display_name"] == "Aarav Kulkarni (Candidate)"
    assert login("verifier").get("/api/auth/me").json()["display_name"] == "TechCorp HR (Verifier)"


# ---------- who may issue ----------
def test_only_registrar_can_issue_and_publish(world):
    files = {"file": ("x.txt", b"hello\n")}
    guest = TestClient(appmod.app)
    assert guest.post("/api/register", files=files).status_code == 401
    for role in ("candidate", "verifier", "auditor"):
        c = login(role)
        assert c.post("/api/register", files={"file": ("x.txt", b"hello\n")}).status_code == 403, role
        assert c.post("/api/publish").status_code == 403, role
        assert c.post("/api/extract", files={"file": ("x.txt", b"hello\n")}).status_code == 403, role


def test_registrar_assigns_candidate_and_stamp_comes_from_session(world):
    r = world.post("/api/register", files={"file": ("diploma.txt", b"Degree\n")},
                   data={"issuer": "NTU", "doc_date": "2026-05-20", "doc_type": "degree",
                         "candidate_name": "  Aarav   Kulkarni "}).json()
    assert r["candidate_name"] == "Aarav Kulkarni" and r["confirmed_by"] == "Chief Registrar Atharva"
    default = world.post("/api/register", files={"file": ("d2.txt", b"Another\n")}).json()
    assert default["candidate_name"] == "Aarav Kulkarni"                      # spec default
    assert "Aarav Kulkarni" in world.get("/api/candidates").json()
    assert "Meera Joshi" in world.get("/api/candidates").json()


def test_extract_suggests_candidate_from_document(world):
    s = world.post("/api/extract", files={"file": ("c.txt", b"This certificate is awarded to Meera Joshi\nIssued by: Orion\n")}).json()
    assert s["candidate_name"] == "Meera Joshi"


# ---------- the consent flow ----------
def test_full_consent_flow(world):
    cand, ver = login("candidate"), login("verifier")

    # candidate sees only what was issued in their name
    vault = cand.get("/api/candidate/documents").json()
    assert [d["name"] for d in vault] == ["certificate_1.txt"] and vault[0]["candidate_name"] == "Aarav Kulkarni"
    assert cand.get("/api/file/1").status_code == 200 and cand.get("/api/proof/1").status_code == 200
    assert cand.get("/api/file/2").status_code == 403                          # Meera's certificate

    # verifier can browse the directory but gets no fingerprints, and cannot open anything yet
    directory = ver.get("/api/records").json()
    assert len(directory) == 5 and all("doc_hash" not in d and "confirmed_by" not in d for d in directory)
    assert all(d["can_access"] is False and d["access_status"] is None for d in directory)
    assert ver.get("/api/file/1").status_code == 403 and ver.get("/api/proof/1").status_code == 403
    assert ver.post("/api/verify-record/1").status_code == 403
    assert TestClient(appmod.app).get("/api/file/1").status_code == 401         # guests are locked out

    # verifier asks; identity comes from the session even if the client lies
    req = ver.post("/api/access/request", data={"record_id": 1, "verifier_name": "Someone Else"}).json()
    assert req["status"] == "pending" and req["verifier_name"] == "TechCorp HR" and req["candidate_name"] == "Aarav Kulkarni"
    assert req["already"] is False and req["responded_at"] is None
    again = ver.post("/api/access/request", data={"record_id": 1}).json()        # no duplicates
    assert again["id"] == req["id"] and again["already"] is True
    assert ver.get("/api/file/1").status_code == 403                             # still locked while pending
    assert ver.get("/api/records").json()[0]["access_status"] == "pending"

    # the right candidate sees it in the inbox; the verifier sees their own request
    inbox = cand.get("/api/access/requests").json()
    assert [(x["id"], x["status"], x["doc_name"]) for x in inbox] == [(req["id"], "pending", "certificate_1.txt")]
    assert [x["id"] for x in ver.get("/api/access/requests").json()] == [req["id"]]
    assert login("meera").get("/api/access/requests").json() == []              # other candidates see nothing

    # approve -> unlocked, and the unlocked bytes verify cryptographically
    done = cand.post(f"/api/access/respond/{req['id']}", data={"action": "approve"}).json()
    assert done["status"] == "approved" and done["responded_at"]
    doc, proof = ver.get("/api/file/1"), ver.get("/api/proof/1")
    assert doc.status_code == 200 and proof.status_code == 200
    res = ver.post("/api/verify", files={"doc": ("certificate_1.txt", doc.content), "proof": ("p.json", proof.content)}).json()
    assert res["code"] == "VERIFIED"
    assert ver.post("/api/verify-record/1").json()["code"] == "VERIFIED"
    assert ver.get("/api/records").json()[0]["can_access"] is True
    assert cand.get("/api/candidate/documents").json()[0]["shared_with"] == ["TechCorp HR"]

    # approval is per record and per verifier
    assert ver.get("/api/file/2").status_code == 403
    assert login("recruiter").get("/api/file/1").status_code == 403

    # candidate can revoke; access disappears immediately
    assert cand.post(f"/api/access/respond/{req['id']}", data={"action": "reject"}).json()["status"] == "rejected"
    assert ver.get("/api/file/1").status_code == 403 and ver.get("/api/proof/1").status_code == 403
    assert ver.post("/api/verify-record/1").status_code == 403


def test_decline_is_final_but_verifier_can_ask_again(world):
    cand, ver = login("candidate"), login("verifier")
    r1 = ver.post("/api/access/request", data={"record_id": 1}).json()
    assert cand.post(f"/api/access/respond/{r1['id']}", data={"action": "reject"}).json()["status"] == "rejected"
    assert ver.get("/api/file/1").status_code == 403
    assert ver.get("/api/records").json()[0]["access_status"] == "rejected"
    assert cand.post(f"/api/access/respond/{r1['id']}", data={"action": "approve"}).status_code == 409   # no re-approve
    assert cand.post(f"/api/access/respond/{r1['id']}", data={"action": "reject"}).status_code == 409
    r2 = ver.post("/api/access/request", data={"record_id": 1}).json()                                   # fresh request is allowed
    assert r2["id"] != r1["id"] and r2["status"] == "pending" and r2["already"] is False
    assert cand.post(f"/api/access/respond/{r2['id']}", data={"action": "approve"}).status_code == 200
    assert cand.post(f"/api/access/respond/{r2['id']}", data={"action": "approve"}).status_code == 409   # already approved
    assert ver.get("/api/file/1").status_code == 200
    assert ver.get("/api/records").json()[0]["access_status"] == "approved"                              # approved wins over old declined


def test_only_the_owner_can_respond_and_only_candidates(world):
    cand, meera, ver = login("candidate"), login("meera"), login("verifier")
    req = ver.post("/api/access/request", data={"record_id": 1}).json()
    assert meera.post(f"/api/access/respond/{req['id']}", data={"action": "approve"}).status_code == 403
    assert ver.post(f"/api/access/respond/{req['id']}", data={"action": "approve"}).status_code == 403     # can't self-approve
    assert login("registrar").post(f"/api/access/respond/{req['id']}", data={"action": "approve"}).status_code == 403
    assert TestClient(appmod.app).post(f"/api/access/respond/{req['id']}", data={"action": "approve"}).status_code == 401
    assert cand.post(f"/api/access/respond/{req['id']}", data={"action": "maybe"}).status_code == 400
    assert cand.post("/api/access/respond/9999", data={"action": "approve"}).status_code == 404
    assert ver.get("/api/file/1").status_code == 403                                                        # nothing slipped through


def test_request_validation_and_role_limits(world):
    cand, ver = login("candidate"), login("verifier")
    assert cand.post("/api/access/request", data={"record_id": 1}).status_code == 403        # candidates don't request
    assert login("registrar").post("/api/access/request", data={"record_id": 1}).status_code == 403
    assert TestClient(appmod.app).post("/api/access/request", data={"record_id": 1}).status_code == 401
    assert ver.post("/api/access/request", data={"record_id": 9999}).status_code == 404
    assert ver.post("/api/access/request", data={"record_id": 1, "candidate_name": "Meera Joshi"}).status_code == 400
    world.post("/api/register", files={"file": ("pending.txt", b"not published yet\n")})
    pending_id = max(r["id"] for r in world.get("/api/records").json())
    assert ver.post("/api/access/request", data={"record_id": pending_id}).status_code == 400   # unpublished
    assert pending_id not in [d["id"] for d in ver.get("/api/records").json()]                 # and not listed
    assert ver.get("/api/candidate/documents").status_code == 403


def test_registrar_and_admin_keep_full_access_auditor_does_not(world):
    for who in ("registrar",):
        c = login(who)
        assert c.get("/api/file/1").status_code == 200 and c.get("/api/proof/1").status_code == 200
        assert "doc_hash" in c.get("/api/records").json()[0]
    admin = TestClient(appmod.app)
    admin.post("/api/auth/login", data={"username": "admin", "password": "admin"})
    assert admin.get("/api/file/1").status_code == 200
    aud = login("auditor")
    assert aud.get("/api/file/1").status_code == 403 and aud.get("/api/proof/1").status_code == 403
    recs = aud.get("/api/records").json()
    assert len(recs) == 5 and recs[0]["can_access"] is False and recs[0]["candidate_name"] == "Aarav Kulkarni"
    assert aud.post("/api/audit").json()["ok"] is True


def test_seed_assigns_each_sample_to_the_person_named_in_it(world):
    by_name = {r["name"]: r["candidate_name"] for r in world.get("/api/records").json()}
    assert by_name == {"certificate_1.txt": "Aarav Kulkarni", "certificate_2.txt": "Meera Joshi",
                       "certificate_3.txt": "Rohan Deshmukh", "certificate_4.txt": "Sneha Patil",
                       "certificate_5.txt": "Kabir Shah"}
    assert [d["name"] for d in login("meera").get("/api/candidate/documents").json()] == ["certificate_2.txt"]


def test_demo_controls_and_audit_are_not_open_to_everyone(world):
    guest = TestClient(appmod.app)
    for role in (None, "candidate", "verifier"):
        c = guest if role is None else login(role)
        want = 401 if role is None else 403
        assert c.post("/api/demo/reset").status_code == want
        assert c.post("/api/demo/seed").status_code == want
        assert c.post("/api/demo/attack/1").status_code == want
        assert c.post("/api/demo/tamper-log").status_code == want
        assert c.post("/api/audit").status_code == want
        assert c.post("/api/naive-verify/1").status_code == want
    assert guest.get("/api/log").status_code == 200                      # the published roots stay public
    assert len(login("registrar").get("/api/records").json()) == 5       # nothing was reset


def test_consent_does_not_break_the_attack_detection(world):
    """Approved access must not weaken the crypto: after a DB-rewrite attack the verifier still gets ROOT_MISMATCH."""
    cand, ver = login("candidate"), login("verifier")
    req = ver.post("/api/access/request", data={"record_id": 1}).json()
    cand.post(f"/api/access/respond/{req['id']}", data={"action": "approve"})
    world.post("/api/demo/attack/1")
    doc, proof = ver.get("/api/file/1"), ver.get("/api/proof/1")
    res = ver.post("/api/verify", files={"doc": ("certificate_1.txt", doc.content), "proof": ("p.json", proof.content)}).json()
    assert res["code"] == "ROOT_MISMATCH"


# ---------- schema migration for databases created before this feature ----------
def test_old_database_is_migrated(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "DATA", tmp_path / "data")
    monkeypatch.setattr(appmod, "FILES", tmp_path / "data" / "files")
    (tmp_path / "data").mkdir()
    old = sqlite3.connect(tmp_path / "data" / "registry.db")
    old.executescript("""CREATE TABLE records(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, file TEXT, doc_hash TEXT,
        issuer TEXT, doc_date TEXT, doc_type TEXT, batch_id TEXT, leaf_index INTEGER, proof TEXT);
        INSERT INTO records(name, file, doc_hash) VALUES('legacy.txt', 'x', 'h');""")
    old.commit(); old.close()
    c = appmod.db()
    cols = {r["name"] for r in c.execute("PRAGMA table_info(records)")}
    assert {"candidate_name", "confirmed_by", "confirmed_at"} <= cols
    assert c.execute("SELECT candidate_name FROM records").fetchone()[0] == "Aarav Kulkarni"    # default for legacy rows
    assert c.execute("SELECT COUNT(*) FROM access_requests").fetchone()[0] == 0
    appmod.db()                                                                                  # idempotent
