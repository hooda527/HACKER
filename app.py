"""Event registration API backed by Supabase."""

import os
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from postgrest import APIError
from supabase import Client, create_client

load_dotenv()

app = Flask(__name__, static_folder="public", static_url_path="")


def get_supabase() -> Client:
    """Create the client lazily so the app can be imported without local secrets."""
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_PUBLISHABLE_KEY") or os.environ.get("SUPABASE_ANON_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be configured")
    return create_client(url, key)


def api_error(message: str, status: int):
    return jsonify({"error": message}), status


def database_error(error: APIError):
    # Avoid returning SQL or connection details to API callers.
    code = getattr(error, "code", None)
    if code == "23505":
        return api_error("Registration already exists", 409)
    if code == "23503":
        return api_error("Referenced user or event does not exist", 400)
    app.logger.exception("Supabase request failed", exc_info=error)
    return api_error("Database request failed", 500)


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/api")
def api_index():
    return jsonify({"service": "events-api", "endpoints": [
        "GET /api/events", "GET /api/events/<id>", "POST /api/registrations",
        "GET /api/me/registrations?user_id=<uuid>",
        "GET /api/events/<id>/registrations?organizer_id=<uuid>",
    ]})


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


@app.post("/api/registrations")
def create_registration():
    body: Any = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("Request body must be a JSON object", 400)
    user_id, event_id = body.get("user_id"), body.get("event_id")
    if not user_id or not event_id:
        return api_error("user_id and event_id are required", 400)

    try:
        db = get_supabase()
        event_result = db.table("events").select("id,capacity,status").eq("id", event_id).limit(1).execute()
        if not event_result.data:
            return api_error("Event not found", 404)
        event = event_result.data[0]

        existing = (db.table("registrations").select("id")
                    .eq("user_id", user_id).eq("event_id", event_id).limit(1).execute())
        if existing.data:
            return api_error("User is already registered for this event", 409)

        capacity = event.get("capacity")
        if capacity is not None:
            current = (db.table("registrations").select("id", count="exact")
                       .eq("event_id", event_id).execute())
            if (current.count or 0) >= capacity:
                return api_error("Event is at capacity", 409)

        result = db.table("registrations").insert({"user_id": user_id, "event_id": event_id}).execute()
        registration = result.data[0] if result.data else {"user_id": user_id, "event_id": event_id}
        return jsonify(registration), 201
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/me/registrations")
def my_registrations():
    # Authentication is intentionally not enabled yet; caller supplies their user UUID.
    user_id = request.args.get("user_id")
    if not user_id:
        return api_error("user_id query parameter is required", 400)
    try:
        result = (get_supabase().table("registrations")
                  .select("*, events(*)").eq("user_id", user_id).execute())
        return jsonify(result.data)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


@app.get("/api/events/<event_id>/registrations")
def event_registrations(event_id: str):
    # Without authentication, organizer_id is a caller-provided identity, not proof of ownership.
    organizer_id = request.args.get("organizer_id")
    if not organizer_id:
        return api_error("organizer_id query parameter is required", 400)
    try:
        db = get_supabase()
        event_result = db.table("events").select("id,organizer_id").eq("id", event_id).limit(1).execute()
        if not event_result.data:
            return api_error("Event not found", 404)
        if event_result.data[0].get("organizer_id") != organizer_id:
            return api_error("Only the event organizer can view its registrations", 403)
        result = (db.table("registrations")
                  .select("*, users(id,email,role)").eq("event_id", event_id).execute())
        return jsonify(result.data)
    except APIError as error:
        return database_error(error)
    except RuntimeError as error:
        return api_error(str(error), 500)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
