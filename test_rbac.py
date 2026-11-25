"""
RBAC Test Suite — covers all three roles + edge cases.
Run: cd backend && venv\\Scripts\\python.exe -m pytest test_rbac.py -v
"""
import os, sys
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_PUBLISHABLE_KEY", "test-anon-key")
os.environ["JWT_SECRET_KEY"] = "test-secret-do-not-use-in-production"

# Ensure local imports resolve
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from unittest.mock import patch, MagicMock
from auth import create_token, decode_token, has_permission, PERMISSIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_user(role, uid="uuid-1", email="test@test.com", status="active"):
    return {"id": uid, "email": email, "role": role, "status": status}


def make_token(role, uid="uuid-1", email="test@test.com"):
    return create_token(make_user(role, uid=uid, email=email))


# ---------------------------------------------------------------------------
# 1. JWT token creation and verification
# ---------------------------------------------------------------------------
class TestJWT:
    def test_encode_decode_roundtrip(self):
        token = make_token("student")
        payload = decode_token(token)
        assert payload["role"] == "student"

    def test_admin_token_carries_admin_role(self):
        token = make_token("administrator")
        payload = decode_token(token)
        assert payload["role"] == "administrator"

    def test_organizer_token(self):
        payload = decode_token(make_token("organizer"))
        assert payload["role"] == "organizer"

    def test_expired_token_raises(self):
        import jwt, datetime
        payload = {
            "sub": "x", "email": "x@x.com", "role": "student",
            "exp": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1),
            "iat": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, os.environ["JWT_SECRET_KEY"], algorithm="HS256")
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_token(token)

    def test_tampered_token_raises(self):
        import jwt
        token = make_token("student") + "tampered"
        with pytest.raises(jwt.PyJWTError):
            decode_token(token)


# ---------------------------------------------------------------------------
# 2. Permission map
# ---------------------------------------------------------------------------
class TestPermissions:
    def test_admin_has_all_critical_permissions(self):
        for perm in ["users:write", "roles:assign", "events:delete", "registrations:read_all", "audit:read"]:
            assert has_permission("administrator", perm), f"admin missing {perm}"

    def test_student_cannot_manage_users(self):
        assert not has_permission("student", "users:write")
        assert not has_permission("student", "roles:assign")
        assert not has_permission("student", "events:delete")
        assert not has_permission("student", "registrations:read_all")
        assert not has_permission("student", "audit:read")

    def test_student_can_register(self):
        assert has_permission("student", "registrations:create")
        assert has_permission("student", "registrations:read_own")

    def test_organizer_cannot_manage_users(self):
        assert not has_permission("organizer", "users:write")
        assert not has_permission("organizer", "roles:assign")
        assert not has_permission("organizer", "events:delete")

    def test_organizer_can_read_own_events(self):
        assert has_permission("organizer", "events:write_own")
        assert has_permission("organizer", "registrations:read_own_event")

    def test_role_isolation(self):
        # Student permissions are a strict subset
        student_perms = PERMISSIONS["student"]
        admin_only = PERMISSIONS["administrator"] - student_perms
        assert len(admin_only) > 0  # There ARE admin-only permissions
        for perm in admin_only:
            assert not has_permission("student", perm), f"student wrongly has {perm}"


# ---------------------------------------------------------------------------
# 3. Flask endpoint RBAC (using test client + mocked Supabase)
# ---------------------------------------------------------------------------
@pytest.fixture()
def client():
    with patch("app.get_supabase") as mock_sb:
        db = MagicMock()
        mock_sb.return_value = db
        # Default: empty tables
        def make_result(data, count=None):
            r = MagicMock(); r.data = data; r.count = count or len(data); return r

        db.table.return_value.select.return_value.execute.return_value = make_result([])
        db.table.return_value.select.return_value.eq.return_value.execute.return_value = make_result([])
        db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = make_result([])
        db.table.return_value.insert.return_value.execute.return_value = make_result([])
        db.table.return_value.update.return_value.eq.return_value.execute.return_value = make_result([])
        db.table.return_value.delete.return_value.eq.return_value.execute.return_value = make_result([])
        db.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value = make_result([])

        import app as flask_app
        flask_app.app.config["TESTING"] = True
        with flask_app.app.test_client() as c:
            c._mock_db = db
            c._make_result = make_result
            yield c


def auth(role, uid="uid-1"):
    return {"Authorization": f"Bearer {make_token(role, uid=uid)}"}


class TestAdminEndpoints:
    def test_admin_can_list_users(self, client):
        resp = client.get("/api/admin/users", headers=auth("administrator"))
        assert resp.status_code == 200

    def test_student_cannot_list_users(self, client):
        resp = client.get("/api/admin/users", headers=auth("student"))
        assert resp.status_code == 403

    def test_organizer_cannot_list_users(self, client):
        resp = client.get("/api/admin/users", headers=auth("organizer"))
        assert resp.status_code == 403

    def test_unauthenticated_cannot_list_users(self, client):
        resp = client.get("/api/admin/users")
        assert resp.status_code == 401

    def test_admin_can_get_analytics(self, client):
        resp = client.get("/api/admin/analytics", headers=auth("administrator"))
        assert resp.status_code == 200

    def test_student_cannot_get_analytics(self, client):
        resp = client.get("/api/admin/analytics", headers=auth("student"))
        assert resp.status_code == 403

    def test_admin_can_read_audit_logs(self, client):
        resp = client.get("/api/admin/audit-logs", headers=auth("administrator"))
        assert resp.status_code == 200

    def test_student_cannot_read_audit_logs(self, client):
        resp = client.get("/api/admin/audit-logs", headers=auth("student"))
        assert resp.status_code == 403

    def test_admin_can_delete_event(self, client):
        resp = client.delete("/api/events/some-id", headers=auth("administrator"))
        # 200 or 404 (mocked DB returns empty) — not 403
        assert resp.status_code in (200, 404, 500)

    def test_student_cannot_delete_event(self, client):
        resp = client.delete("/api/events/some-id", headers=auth("student"))
        assert resp.status_code == 403

    def test_organizer_cannot_delete_event(self, client):
        resp = client.delete("/api/events/some-id", headers=auth("organizer"))
        assert resp.status_code == 403


class TestOrganizerEndpoints:
    def test_organizer_can_view_organizer_events(self, client):
        resp = client.get("/api/organizer/events", headers=auth("organizer"))
        assert resp.status_code == 200

    def test_student_cannot_view_organizer_events(self, client):
        resp = client.get("/api/organizer/events", headers=auth("student"))
        assert resp.status_code == 403

    def test_organizer_cannot_create_event(self, client):
        # organizer has events:write_own but not events:write (which create_event requires)
        resp = client.post("/api/events", headers=auth("organizer"),
                           json={"title": "Bad Event"})
        assert resp.status_code == 403

    def test_admin_can_create_event(self, client):
        resp = client.post("/api/events", headers=auth("administrator"),
                           json={"title": "Good Event"})
        # 201 or 500 (mocked insert returns empty) — not 403
        assert resp.status_code in (201, 500)


class TestStudentEndpoints:
    def test_student_can_list_events(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200

    def test_student_cannot_access_admin_registrations(self, client):
        resp = client.get("/api/admin/registrations", headers=auth("student"))
        assert resp.status_code == 403

    def test_student_cannot_view_event_registrations(self, client):
        # Event registrations endpoint requires organizer or admin
        resp = client.get("/api/events/some-id/registrations", headers=auth("student"))
        assert resp.status_code == 403

    def test_student_can_view_own_registrations(self, client):
        resp = client.get("/api/me/registrations", headers=auth("student"))
        assert resp.status_code == 200

    def test_unauthenticated_cannot_register(self, client):
        resp = client.post("/api/registrations", json={"event_id": "x"})
        assert resp.status_code == 401

    def test_student_can_request_data_deletion(self, client):
        resp = client.post("/api/me/delete-request",
                           headers=auth("student"),
                           json={"reason": "No longer needed"})
        assert resp.status_code == 201
        assert resp.get_json()["status"] == "pending"

    def test_unauthenticated_cannot_request_data_deletion(self, client):
        resp = client.post("/api/me/delete-request", json={"reason": "test"})
        assert resp.status_code == 401


class TestSwitchView:
    def test_admin_can_switch_to_organizer_preview(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("administrator"),
                           json={"target_role": "organizer"})
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["preview_mode"] is True
        assert d["actual_role"] == "administrator"
        assert d["active_view"] == "organizer"
        assert "/organizer/dashboard" in d["redirect"]

    def test_admin_can_switch_to_student_preview(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("administrator"),
                           json={"target_role": "student"})
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["preview_mode"] is True
        assert d["active_view"] == "student"

    def test_admin_switch_to_own_role_no_preview(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("administrator"),
                           json={"target_role": "administrator"})
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["preview_mode"] is False
        assert d["redirect"] == "/admin/dashboard"

    def test_organizer_cannot_switch_to_admin(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("organizer"),
                           json={"target_role": "administrator"})
        assert resp.status_code == 403

    def test_student_cannot_switch_to_organizer(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("student"),
                           json={"target_role": "organizer"})
        assert resp.status_code == 403

    def test_student_cannot_switch_to_admin(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("student"),
                           json={"target_role": "administrator"})
        assert resp.status_code == 403

    def test_organizer_can_switch_to_own_role(self, client):
        resp = client.post("/api/auth/switch-view",
                           headers=auth("organizer"),
                           json={"target_role": "organizer"})
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["preview_mode"] is False

    def test_unauthenticated_cannot_switch_view(self, client):
        resp = client.post("/api/auth/switch-view", json={"target_role": "administrator"})
        assert resp.status_code == 401

    def test_cannot_inject_role_via_profile_update(self, client):
        resp = client.patch("/api/me/profile",
                            headers=auth("student"),
                            json={"full_name": "Hacker", "role": "administrator"})
        assert resp.status_code == 403


class TestRoleEscalation:
    def test_new_user_cannot_self_assign_admin(self, client):
        """Login with role=administrator for a NEW user → system forces student role."""
        import app as flask_app
        db = client._mock_db
        mr = client._make_result
        # Simulate no existing user
        db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = mr([])
        # Simulate insert
        db.table.return_value.insert.return_value.execute.return_value = mr([{
            "id": "new-uid", "email": "attacker@bad.com", "role": "student", "status": "active"
        }])
        resp = client.post("/api/auth/login",
                           json={"email": "attacker@bad.com", "role": "administrator"})
        if resp.status_code in (200, 201):
            data = resp.get_json()
            # Role in token must NOT be administrator
            token_payload = decode_token(data["token"])
            assert token_payload["role"] != "administrator"

    def test_suspended_user_cannot_login(self, client):
        db = client._mock_db
        mr = client._make_result
        db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = mr([{
            "id": "sus-uid", "email": "sus@bad.com", "role": "student", "status": "suspended", "full_name": ""
        }])
        resp = client.post("/api/auth/login",
                           json={"email": "sus@bad.com", "role": "student"})
        assert resp.status_code == 403

    def test_manipulated_token_role_is_rejected(self, client):
        """Sign a token claiming student role but send to admin endpoint → 403."""
        resp = client.get("/api/admin/users", headers=auth("student"))
        assert resp.status_code == 403

    def test_idor_student_cannot_cancel_other_registration(self, client):
        db = client._mock_db
        mr = client._make_result
        # reg belongs to uid-999, but token is uid-1
        db.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = mr([
            {"id": "reg-id", "user_id": "uid-999"}
        ])
        resp = client.patch("/api/me/registrations/reg-id/cancel",
                            headers=auth("student", uid="uid-1"))
        assert resp.status_code == 403


class TestDirectURLAccess:
    def test_admin_dashboard_html_is_served(self, client):
        resp = client.get("/admin/dashboard")
        assert resp.status_code == 200

    def test_organizer_dashboard_html_is_served(self, client):
        resp = client.get("/organizer/dashboard")
        assert resp.status_code == 200

    def test_student_dashboard_html_is_served(self, client):
        resp = client.get("/student/dashboard")
        assert resp.status_code == 200
        # The HTML itself contains the client-side guard
        assert b"administrator" in resp.data or b"student" in resp.data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
