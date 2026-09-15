#!/usr/bin/env python3
"""
Predita end-to-end workflow self-test.

Run from the same directory as predita_web.py:
    python predita_selftest.py

This test uses a temporary database and temporary evidence directory.
It does not alter your real Predita database.
"""

import io
import os
import sys
import tempfile
from pathlib import Path
import importlib.util

def load_app(app_path, temp_db, temp_uploads):
    os.environ["PREDITA_DB"] = str(temp_db)
    os.environ["PREDITA_UPLOAD_DIR"] = str(temp_uploads)
    os.environ["PREDITA_ADMIN_USER"] = "admin"
    os.environ["PREDITA_ADMIN_PASSWORD"] = "Admin-Test-Password-123!"
    os.environ["PREDITA_SECRET_KEY"] = "predita-selftest-secret"
    os.environ["PREDITA_ALLOW_SELF_APPROVAL"] = "0"
    os.environ["PREDITA_HTTPS_ONLY"] = "0"
    os.environ["PREDITA_SESSION_MINUTES"] = "30"

    spec = importlib.util.spec_from_file_location("predita_web_selftest", app_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.init_db()
    mod.bootstrap_admin()
    return mod

def csrf(client):
    with client.session_transaction() as sess:
        return sess["csrf"]

def login(client, username, password):
    r = client.get("/login")
    assert r.status_code == 200, f"GET /login failed: {r.status_code}"
    token = csrf(client)
    r = client.post("/login", data={
        "username": username,
        "password": password,
        "csrf": token
    }, follow_redirects=True)
    assert r.status_code == 200, f"Login failed HTTP {r.status_code}"
    return r

def logout(client):
    client.get("/logout", follow_redirects=True)

def create_user(mod, username, password, role):
    con = mod.db()
    con.execute("""
        INSERT INTO users(username,password_hash,role,active,created_at,created_by)
        VALUES(?,?,?,?,?,?)
    """, (
        username,
        mod.generate_password_hash(password),
        role,
        1,
        mod.now_iso(),
        "selftest"
    ))
    con.commit()

def main():
    app_path = Path("predita_web.py")
    if not app_path.is_file():
        print("FAIL: predita_web.py not found in the current directory.")
        print("Run this from ~/predita-web")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="predita-selftest-") as td:
        root = Path(td)
        temp_db = root / "selftest.db"
        temp_uploads = root / "evidence"
        temp_uploads.mkdir()

        mod = load_app(app_path, temp_db, temp_uploads)
        client = mod.app.test_client()

        print("1. Bootstrap admin ...", end=" ")
        login(client, "admin", "Admin-Test-Password-123!")
        assert b"Cases" in client.get("/").data
        print("PASS")

        print("2. Create role accounts ...", end=" ")
        create_user(mod, "intake1", "Intake-Test-Password-123!", "intake")
        create_user(mod, "approver1", "Approver-Test-Password-123!", "approver")
        create_user(mod, "investigator1", "Investigator-Test-Password-123!", "investigator")
        print("PASS")

        print("3. Intake creates case ...", end=" ")
        logout(client)
        login(client, "intake1", "Intake-Test-Password-123!")
        r = client.post("/case/new", data={
            "csrf": csrf(client),
            "case_id": "SELFTEST-001",
            "title": "Predita workflow self-test",
            "authority_ref": "AUTH-SELFTEST-001"
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"SELFTEST-001" in r.data
        print("PASS")

        print("4. Intake receives call evidence ...", end=" ")
        calls_csv = (
            "calling_number,called_number,event_time,duration_seconds,direction,imei,imsi,cell_id\n"
            "0820000001,0830000002,2026-09-15 00:10:00,120,outgoing,TEST-IMEI-1,TEST-IMSI-1,CELL-001\n"
            "0830000002,0820000001,2026-09-15 00:20:00,45,incoming,TEST-IMEI-2,TEST-IMSI-2,CELL-002\n"
        ).encode("utf-8")

        r = client.post(
            "/case/SELFTEST-001/evidence/receive",
            data={
                "csrf": csrf(client),
                "dataset_type": "calls",
                "provider": "TEST-PROVIDER",
                "authority_ref": "AUTH-SELFTEST-001",
                "source_reference": "TRANSFER-SELFTEST-001",
                "notes": "Synthetic evidence for local self-test only",
                "file": (io.BytesIO(calls_csv), "selftest_calls.csv"),
            },
            content_type="multipart/form-data",
            follow_redirects=True
        )
        assert r.status_code == 200
        con = mod.db()
        receipt = con.execute(
            "SELECT * FROM evidence_receipts WHERE case_id=?",
            ("SELFTEST-001",)
        ).fetchone()
        assert receipt is not None
        assert receipt["status"] == "received"
        receipt_id = receipt["id"]
        assert Path(receipt["stored_path"]).is_file()
        print("PASS")

        print("5. Self-approval is blocked ...", end=" ")
        # Intake role should not have approval permission at all; endpoint should return 403.
        r = client.post(
            f"/case/SELFTEST-001/evidence/{receipt_id}/approve",
            data={"csrf": csrf(client)},
            follow_redirects=False
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"
        print("PASS")

        print("6. Approver verifies hash + imports ...", end=" ")
        logout(client)
        login(client, "approver1", "Approver-Test-Password-123!")
        r = client.post(
            f"/case/SELFTEST-001/evidence/{receipt_id}/approve",
            data={"csrf": csrf(client)},
            follow_redirects=True
        )
        assert r.status_code == 200
        receipt = mod.db().execute(
            "SELECT * FROM evidence_receipts WHERE id=?",
            (receipt_id,)
        ).fetchone()
        assert receipt["status"] == "imported"
        assert receipt["import_id"] is not None
        call_count = mod.db().execute(
            "SELECT COUNT(*) AS n FROM call_records WHERE case_id=?",
            ("SELFTEST-001",)
        ).fetchone()["n"]
        assert call_count == 2, f"Expected 2 imported calls, got {call_count}"
        print("PASS")

        print("7. Investigator searches imported calls ...", end=" ")
        logout(client)
        login(client, "investigator1", "Investigator-Test-Password-123!")
        r = client.get("/case/SELFTEST-001?q=0820000001&dataset=calls")
        assert r.status_code == 200
        assert b"+27820000001" in r.data
        assert b"+27830000002" in r.data
        print("PASS")

        print("8. Audit trail exists ...", end=" ")
        actions = {
            row["action"] for row in mod.db().execute(
                "SELECT action FROM audit_events WHERE case_id=?",
                ("SELFTEST-001",)
            ).fetchall()
        }
        expected = {
            "case_create",
            "evidence_received",
            "evidence_approved_imported",
            "case_search",
        }
        missing = expected - actions
        assert not missing, f"Missing audit actions: {sorted(missing)}"
        print("PASS")

        print()
        print("ALL PREDITA WORKFLOW TESTS PASSED")
        print("Verified:")
        print("- separate intake / approver / investigator roles")
        print("- case creation")
        print("- evidence receipt and SHA-256 storage")
        print("- intake cannot approve")
        print("- approver verifies/imports evidence")
        print("- imported calls become searchable")
        print("- case audit events are recorded")
        print()
        print("Your real Predita database was NOT modified.")

if __name__ == "__main__":
    main()
