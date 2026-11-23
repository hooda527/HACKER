# Events API

Flask API for the `users`, `events`, and `registrations` tables shown in `database.png`.

## Setup

Install dependencies and set these values in `.env`:

```text
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_PUBLISHABLE_KEY=your-publishable-key
```

`SUPABASE_ANON_KEY` is also accepted as a legacy alternative. Run with
`python app.py` (or `flask --app app run`).

## Deploy to Render

Create a Render web service from this repository and use the included
`render.yaml` Blueprint, or configure the service with:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`
- Health check path: `/`

Set `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` in the Render service's
environment. Use the publishable (or legacy anon) key, never a Supabase
secret/service-role key in a public web service.

## Routes

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/events` | Browse events |
| GET | `/api/events/{id}` | Event details; returns 404 when missing |
| POST | `/api/registrations` | Create a registration; returns 201, or 409 for duplicate/full event |
| GET | `/api/me/registrations?user_id={uuid}` | List registrations for the supplied user ID |
| GET | `/api/events/{id}/registrations?organizer_id={uuid}` | List attendees if the supplied ID matches the event organizer |

Registration body:

```json
{"user_id":"<users.id>","event_id":"<events.id>"}
```

Authentication is intentionally absent. The IDs supplied to the two private-list
routes are caller claims, not verified identity; add authentication before exposing
this API publicly. Capacity is checked before inserting, so concurrent requests
can race at capacity. A database constraint or transactional RPC is needed for a
strict capacity guarantee.

The registrations attendee query expects a foreign key from `registrations.user_id`
to `users.id`, as indicated by the schema diagram. Supabase Data API grants and
RLS policies must also permit the operations for the configured publishable key.
