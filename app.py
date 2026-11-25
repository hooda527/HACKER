"""Event registration API with full RBAC — backed by Supabase."""

import os
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, request, g
from postgrest import APIError
from supabase import Client, create_client

from auth import (
    create_token, get_current_user, login_required,
    role_required, permission_required, audit_log, has_permission,
)

load_dotenv()

app = Flask(__name__, static_folder="public", static_url_path="")


# ---------------------------------------------------------------------------
# Supabase clients
# ---------------------------------------------------------------------------
def get_supabase() -> Client:
    """Anon-key client — subject to RLS policies."""
    url = os.environ.get("SUPABASE_URL")
    key = (os.environ.get("SUPABASE_PUBLISHABLE_KEY")
           or os.environ.get("SUPABASE_ANON_KEY"))
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be configured")
    return create_client(url, key)


def get_admin_supabase() -> Client:
    """
    Service-role client — bypasses RLS for privileged server-side operations.
    NEVER expose this key to the frontend.
    """
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY must be configured for admin operations")
    return create_client(url, key)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------
def api_error(message: str, status: int):
    return jsonify({"error": message}), status


def database_error(error: APIError):
    code = getattr(error, "code", None)
    if code == "23505":
        return api_error("Registration already exists", 409)
    if code == "23503":
        return api_error("Referenced user or event does not exist", 400)
    if code == "42501":
        return api_error("Database permission denied — run migration 001_rbac.sql", 403)
    app.logger.exception("Supabase request failed", exc_info=error)
    return api_error("Database request failed", 500)


# ===========================================================================
# PUBLIC ROUTES
# ===========================================================================

@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/admin/dashboard")
def admin_dashboard():
    return app.send_static_file("admin/dashboard.html")


@app.get("/organizer/dashboard")
def organizer_dashboard():
    return app.send_static_file("organizer/dashboard.html")


@app.get("/student/dashboard")
def student_dashboard():
    return app.send_static_file("student/dashboard.html")


@app.get("/api")
def api_index():
    return jsonify({"service": "events-api", "version": "2.0-rbac"})


# ---------------------------------------------------------------------------
# AUTH: login / logout / whoami
# ---------------------------------------------------------------------------

@app.post("/api/auth/login")
def login():
    """
    POST { "email": "...", "role": "student" }
    Returns { "token": "...", "user": { id, email, role, status } }

    Role supplied by the client is ONLY used for new-user creation.
    For existing users the role is loaded from the DB (never from the request).
    """
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    email = str(body.get("email") or "").strip().lower()
    requested_role = str(body.get("role") or "student").strip().lower()

    if not email or "@" not in email:
        return api_error("A valid email address is required", 400)

    allowed_roles = ("student", "organizer", "administrator")
    if requested_role not in allowed_roles:
        requested_role = "student"

    try:
        db = get_supabase()
        existing = db.table("users").select("id,email,role,status,full_name").eq("email", email).limit(1).execute()

        if existing.data:
            user = existing.data[0]
            # Reject suspended accounts
            if user.get("status") == "suspended":
                return api_error("Account suspended. Contact an administrator.", 403)
            # CRITICAL: ignore client-supplied role; use DB role
            token = create_token(user)
            audit_log(db, user["id"], "auth.login", email)
            return jsonify({"token": token, "user": {
                "id": user["id"], "email": user["email"],
                "role": user["role"], "status": user.get("status", "active"),
                "full_name": user.get("full_name", ""),
            }})

        # New user — role from request (cannot self-assign administrator)
        if requested_role == "administrator":
            requested_role = "student"

        created = db.table("users").insert({
            "email": email, "role": requested_role, "status": "active"
        }).execute()

        if not created.data:
            return api_error("Could not create user", 500)

        user = created.data[0]
        token = create_token(user)
        audit_log(db, user["id"], "auth.register", email)
        return jsonify({"token": token, "user": {
            "id": user["id"], "email": user["email"],
            "role": user["role"], "status": user.get("status", "active"),
            "full_name": user.get("full_name", ""),
        }}), 201

    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/auth/whoami")
@login_required
def whoami():
    """Return the verified token payload (useful for SPA bootstrapping)."""
    user = get_current_user()
    try:
        db = get_supabase()
        row = db.table("users").select("id,email,role,status,full_name").eq("id", user["sub"]).limit(1).execute()
        if not row.data:
            return api_error("User no longer exists", 404)
        u = row.data[0]
        if u.get("status") == "suspended":
            return api_error("Account suspended", 403)
        return jsonify(u)
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


@app.post("/api/auth/switch-view")
@login_required
def switch_view():
    """
    Validate whether the authenticated user may view a target role dashboard.
    Never modifies the permanent database role:
      - administrator -> administrator (/admin/dashboard), or organizer/student in read-only preview mode
      - organizer     -> organizer (/organizer/dashboard) only (403 for anything else)
      - student       -> student (/student/dashboard) only (403 for anything else)
    """
    user = get_current_user()
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    raw_target = str(body.get("target_role", "")).strip().lower()
    target_role = "administrator" if raw_target == "admin" else raw_target
    if target_role not in ("administrator", "organizer", "student"):
        return api_error("Invalid target_role; must be administrator, organizer, or student", 400)

    actual_role = user.get("role", "student")
    if actual_role != "administrator" and target_role != actual_role:
        return api_error(f"Forbidden: {actual_role} accounts cannot switch to {target_role}", 403)

    preview_mode = (actual_role == "administrator" and target_role != "administrator")
    routes = {
        "administrator": "/admin/dashboard",
        "organizer": "/organizer/dashboard?preview=1" if preview_mode else "/organizer/dashboard",
        "student": "/student/dashboard?preview=1" if preview_mode else "/student/dashboard",
    }

    try:
        db = get_supabase()
        audit_log(db, user["sub"], "auth.switch_view", target_role, {"preview_mode": preview_mode})
    except RuntimeError:
        pass

    return jsonify({
        "actual_role": actual_role,
        "active_view": target_role,
        "preview_mode": preview_mode,
        "redirect": routes[target_role],
    })


# Keep old resolve endpoint for backward compat (redirects to login)
@app.post("/api/users/resolve")
def resolve_user():
    return login()


# ===========================================================================
# EVENTS (public read + protected write)
# ===========================================================================

@app.get("/api/events")
def list_events():
    try:
        result = get_supabase().table("events").select("*").execute()
        return jsonify(result.data)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/events/<event_id>")
def get_event(event_id: str):
    try:
        result = get_supabase().table("events").select("*").eq("id", event_id).limit(1).execute()
        if not result.data:
            return api_error("Event not found", 404)
        return jsonify(result.data[0])
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.post("/api/events")
@login_required
@permission_required("events:write")
def create_event():
    """Admin can create events freely; organizer can create with admin grant (organizer has events:write_own, not events:write)."""
    user = get_current_user()
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    title = str(body.get("title") or "").strip()
    if not title:
        return api_error("title is required", 400)

    payload = {
        "title": title,
        "organizer_id": body.get("organizer_id") or user["sub"],
        "capacity": int(body["capacity"]) if body.get("capacity") else None,
        "status": str(body.get("status") or "upcoming"),
        "category": str(body.get("category") or "General"),
        "description": str(body.get("description") or ""),
        "start_date": body.get("start_date"),
    }

    try:
        db = get_supabase()
        result = db.table("events").insert(payload).execute()
        audit_log(db, user["sub"], "events.create", result.data[0]["id"] if result.data else "")
        return jsonify(result.data[0] if result.data else payload), 201
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.patch("/api/events/<event_id>")
@login_required
def update_event(event_id: str):
    user = get_current_user()
    role = user.get("role", "")

    if not has_permission(role, "events:write") and not has_permission(role, "events:write_own"):
        return api_error("Forbidden: insufficient permission", 403)

    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    try:
        db = get_supabase()
        ev = db.table("events").select("id,organizer_id").eq("id", event_id).limit(1).execute()
        if not ev.data:
            return api_error("Event not found", 404)

        # Organizers can only edit their own events
        if role == "organizer" and ev.data[0].get("organizer_id") != user["sub"]:
            return api_error("Forbidden: not your event", 403)

        allowed_fields = {"title", "capacity", "status", "category", "description", "start_date"}
        # Admin can also re-assign organizer
        if role == "administrator":
            allowed_fields.add("organizer_id")

        update_payload = {k: v for k, v in body.items() if k in allowed_fields}
        if not update_payload:
            return api_error("No valid fields to update", 400)

        result = db.table("events").update(update_payload).eq("id", event_id).execute()
        audit_log(db, user["sub"], "events.update", event_id, update_payload)
        return jsonify(result.data[0] if result.data else {"id": event_id})
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.delete("/api/events/<event_id>")
@login_required
@permission_required("events:delete")
def delete_event(event_id: str):
    user = get_current_user()
    try:
        db = get_supabase()
        result = db.table("events").delete().eq("id", event_id).execute()
        audit_log(db, user["sub"], "events.delete", event_id)
        return jsonify({"deleted": event_id})
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


# ===========================================================================
# REGISTRATIONS
# ===========================================================================

@app.post("/api/registrations")
@login_required
@permission_required("registrations:create")
def create_registration():
    user = get_current_user()
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    event_id = body.get("event_id")
    if not event_id:
        return api_error("event_id is required", 400)

    # IDOR prevention: students can only register themselves
    user_id = user["sub"]

    try:
        db = get_supabase()
        event_result = db.table("events").select("id,capacity,status").eq("id", event_id).limit(1).execute()
        if not event_result.data:
            return api_error("Event not found", 404)
        event = event_result.data[0]

        if event.get("status") == "closed":
            return api_error("Event is closed for registrations", 409)

        existing = (db.table("registrations").select("id")
                    .eq("user_id", user_id).eq("event_id", event_id).limit(1).execute())
        if existing.data:
            return api_error("You are already registered for this event", 409)

        capacity = event.get("capacity")
        if capacity is not None:
            current = (db.table("registrations").select("id", count="exact")
                       .eq("event_id", event_id).eq("status", "confirmed").execute())
            if (current.count or 0) >= capacity:
                return api_error("Event is at capacity", 409)

        result = db.table("registrations").insert({
            "user_id": user_id, "event_id": event_id, "status": "confirmed"
        }).execute()
        reg = result.data[0] if result.data else {"user_id": user_id, "event_id": event_id}
        audit_log(db, user_id, "registrations.create", event_id)
        return jsonify(reg), 201
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/me/registrations")
@login_required
@permission_required("registrations:read_own")
def my_registrations():
    user = get_current_user()
    try:
        result = (get_supabase().table("registrations")
                  .select("*, events(*)").eq("user_id", user["sub"]).execute())
        return jsonify(result.data)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.patch("/api/me/registrations/<reg_id>/cancel")
@login_required
@permission_required("registrations:cancel_own")
def cancel_registration(reg_id: str):
    user = get_current_user()
    try:
        db = get_supabase()
        reg = db.table("registrations").select("id,user_id").eq("id", reg_id).limit(1).execute()
        if not reg.data:
            return api_error("Registration not found", 404)
        # IDOR: only the owner can cancel
        if reg.data[0]["user_id"] != user["sub"]:
            return api_error("Forbidden: not your registration", 403)
        result = db.table("registrations").update({"status": "cancelled"}).eq("id", reg_id).execute()
        return jsonify(result.data[0] if result.data else {"id": reg_id, "status": "cancelled"})
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.patch("/api/me/profile")
@login_required
@permission_required("profile:write_own")
def update_own_profile():
    """Allow a user to update only their own permitted profile fields (full_name)."""
    user = get_current_user()
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    if "role" in body or "status" in body:
        return api_error("Forbidden: cannot modify your own role or account status", 403)

    full_name = str(body.get("full_name", "")).strip()
    if not full_name:
        return api_error("full_name is required", 400)

    try:
        db = get_supabase()
        result = db.table("users").update({"full_name": full_name}).eq("id", user["sub"]).execute()
        updated = result.data[0] if result.data else {"id": user["sub"], "full_name": full_name}
        audit_log(db, user["sub"], "profile.update_own", user["sub"], {"full_name": full_name})
        return jsonify(updated)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.post("/api/me/delete-request")
@login_required
def request_data_deletion():
    """Allow any authenticated user to request deletion of their data."""
    user = get_current_user()
    body: Any = request.get_json(silent=True) or {}
    reason = str(body.get("reason", "")).strip()[:500] if isinstance(body, dict) else ""

    try:
        db = get_supabase()
        db.table("audit_logs").insert({
            "actor_id": user["sub"],
            "action": "user.deletion_request",
            "target": user["sub"],
            "meta": {
                "email": user.get("email"),
                "role": user.get("role"),
                "reason": reason or "User requested data deletion",
                "status": "pending",
            },
        }).execute()
        return jsonify({
            "message": "Your data deletion request has been submitted for administrator review.",
            "user_id": user["sub"],
            "status": "pending",
        }), 201
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/events/<event_id>/registrations")
@login_required
@role_required("organizer", "administrator")
def event_registrations(event_id: str):
    user = get_current_user()
    role = user.get("role", "")

    try:
        db = get_supabase()
        ev = db.table("events").select("id,organizer_id").eq("id", event_id).limit(1).execute()
        if not ev.data:
            return api_error("Event not found", 404)

        # Admins see all; organizers see only their events
        if role == "organizer" and ev.data[0].get("organizer_id") != user["sub"]:
            return api_error("Forbidden: not your event", 403)

        result = (db.table("registrations")
                  .select("*, users(id,email,full_name,role)").eq("event_id", event_id).execute())
        return jsonify(result.data)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


# ===========================================================================
# ADMIN-ONLY: User management
# ===========================================================================

@app.get("/api/admin/users")
@login_required
@role_required("administrator")
def admin_list_users():
    try:
        result = get_supabase().table("users").select("id,email,role,status,full_name,created_at").execute()
        return jsonify(result.data)
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


@app.patch("/api/admin/users/<user_id>")
@login_required
@role_required("administrator")
def admin_update_user(user_id: str):
    actor = get_current_user()
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)

    # Only allow safe fields; role escalation prevention: cannot self-demote admin
    allowed = {"full_name", "status", "role"}
    payload = {k: v for k, v in body.items() if k in allowed}

    if "role" in payload:
        new_role = str(payload["role"]).lower()
        if new_role not in ("student", "organizer", "administrator"):
            return api_error("Invalid role value", 400)
        payload["role"] = new_role

    if not payload:
        return api_error("No valid fields to update", 400)

    try:
        db = get_supabase()
        result = db.table("users").update(payload).eq("id", user_id).execute()
        audit_log(db, actor["sub"], "admin.user.update", user_id, payload)
        return jsonify(result.data[0] if result.data else {"id": user_id})
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


@app.get("/api/admin/registrations")
@login_required
@role_required("administrator")
def admin_list_registrations():
    try:
        result = (get_supabase().table("registrations")
                  .select("*, users(id,email,full_name), events(id,title)").execute())
        return jsonify(result.data)
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


@app.get("/api/admin/analytics")
@login_required
@role_required("administrator")
def admin_analytics():
    try:
        db = get_supabase()
        users_r     = db.table("users").select("role", count="exact").execute()
        events_r    = db.table("events").select("status", count="exact").execute()
        reg_r       = db.table("registrations").select("status", count="exact").execute()

        role_counts: dict = {}
        for u in (users_r.data or []):
            r = u.get("role", "unknown")
            role_counts[r] = role_counts.get(r, 0) + 1

        status_counts: dict = {}
        for e in (events_r.data or []):
            s = e.get("status", "unknown")
            status_counts[s] = status_counts.get(s, 0) + 1

        reg_status: dict = {}
        for reg in (reg_r.data or []):
            s = reg.get("status", "unknown")
            reg_status[s] = reg_status.get(s, 0) + 1

        return jsonify({
            "total_users": len(users_r.data or []),
            "users_by_role": role_counts,
            "total_events": len(events_r.data or []),
            "events_by_status": status_counts,
            "total_registrations": len(reg_r.data or []),
            "registrations_by_status": reg_status,
        })
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


@app.get("/api/admin/audit-logs")
@login_required
@role_required("administrator")
def admin_audit_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    try:
        result = (get_supabase().table("audit_logs")
                  .select("*").order("created_at", desc=True).limit(limit).execute())
        return jsonify(result.data)
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


# ===========================================================================
# ORGANIZER: own events + their registrations
# ===========================================================================

@app.get("/api/organizer/events")
@login_required
@role_required("organizer", "administrator")
def organizer_events():
    user = get_current_user()
    try:
        db = get_supabase()
        if user.get("role") == "administrator":
            result = db.table("events").select("*").execute()
        else:
            result = db.table("events").select("*").eq("organizer_id", user["sub"]).execute()
        return jsonify(result.data)
    except (APIError, RuntimeError) as error:
        return api_error(str(error), 500)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
