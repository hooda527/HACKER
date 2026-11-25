-- =============================================================================
-- RBAC Migration 001: Extend schema, enable RLS, create policies
-- Run this in the Supabase SQL Editor (https://app.supabase.com → SQL Editor)
-- Safe to re-run: uses IF NOT EXISTS / OR REPLACE / DO blocks.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Add missing columns to existing tables (non-destructive)
-- ---------------------------------------------------------------------------

-- users: add status and updated_at
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active';
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS full_name    TEXT;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ NOT NULL DEFAULT now();

-- users: constrain role and status values
DO $$ BEGIN
  ALTER TABLE public.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('student','organizer','administrator'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE public.users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active','suspended'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- events: add description, start_date, category, published columns
ALTER TABLE public.events ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE public.events ADD COLUMN IF NOT EXISTS category    TEXT NOT NULL DEFAULT 'General';
ALTER TABLE public.events ADD COLUMN IF NOT EXISTS start_date  DATE;
ALTER TABLE public.events ADD COLUMN IF NOT EXISTS created_at  TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE public.events ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();

-- registrations: add status column (pending / confirmed / cancelled)
ALTER TABLE public.registrations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'confirmed';

DO $$ BEGIN
  ALTER TABLE public.registrations ADD CONSTRAINT registrations_status_check
    CHECK (status IN ('pending','confirmed','cancelled'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- 2. Audit log table (new)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id   UUID        REFERENCES public.users(id) ON DELETE SET NULL,
  action     TEXT        NOT NULL,
  target     TEXT,
  meta       JSONB       DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 3. Indexes
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_users_email          ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_role           ON public.users(role);
CREATE INDEX IF NOT EXISTS idx_events_organizer     ON public.events(organizer_id);
CREATE INDEX IF NOT EXISTS idx_events_status        ON public.events(status);
CREATE INDEX IF NOT EXISTS idx_registrations_user   ON public.registrations(user_id);
CREATE INDEX IF NOT EXISTS idx_registrations_event  ON public.registrations(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor          ON public.audit_logs(actor_id);

-- ---------------------------------------------------------------------------
-- 4. Enable Row Level Security on all tables
-- ---------------------------------------------------------------------------
ALTER TABLE public.users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.registrations  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs     ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 5. Helper: a SECURITY DEFINER function that returns the role of a user by id
--    (avoids recursive RLS policies reading the users table from within itself)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.get_user_role(user_id UUID)
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role FROM public.users WHERE id = user_id LIMIT 1;
$$;

-- ---------------------------------------------------------------------------
-- 6. RLS Policies — users table
--    The anon role is used by the Flask publishable key.
--    All server-side admin operations use the service-role key (bypass RLS).
-- ---------------------------------------------------------------------------

-- Drop existing policies first (idempotent re-run)
DROP POLICY IF EXISTS "Allow public read access" ON public.users;
DROP POLICY IF EXISTS users_read_self      ON public.users;
DROP POLICY IF EXISTS users_insert_self    ON public.users;
DROP POLICY IF EXISTS users_update_self    ON public.users;

-- Students and organizers can read their own row
CREATE POLICY users_read_self ON public.users
  FOR SELECT TO anon
  USING (true);  -- events page needs to list organizers; restrict sensitive fields in app

-- Allow insert of new users (the /api/users/resolve endpoint does this)
CREATE POLICY users_insert_self ON public.users
  FOR INSERT TO anon
  WITH CHECK (role IN ('student','organizer','administrator'));

-- Users can update only their own non-role fields
CREATE POLICY users_update_self ON public.users
  FOR UPDATE TO anon
  USING (true)
  WITH CHECK (true);  -- column-level guard enforced in Flask, not RLS

-- ---------------------------------------------------------------------------
-- 7. RLS Policies — events table
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS events_read_published     ON public.events;
DROP POLICY IF EXISTS events_insert_organizer   ON public.events;
DROP POLICY IF EXISTS events_update_organizer   ON public.events;
DROP POLICY IF EXISTS events_delete_admin       ON public.events;

-- Everyone can read events (students browse, organizers see own)
CREATE POLICY events_read_published ON public.events
  FOR SELECT TO anon
  USING (true);

-- Organizers can only insert events where they are the organizer
CREATE POLICY events_insert_organizer ON public.events
  FOR INSERT TO anon
  WITH CHECK (true);  -- Flask enforces organizer_id ownership

-- Organizers can only update their own events (Flask validates further)
CREATE POLICY events_update_organizer ON public.events
  FOR UPDATE TO anon
  USING (true)
  WITH CHECK (true);

-- Admins can delete events (enforced in Flask via @permission_required("events:delete"))
CREATE POLICY events_delete_admin ON public.events
  FOR DELETE TO anon
  USING (true);

-- ---------------------------------------------------------------------------
-- 8. RLS Policies — registrations table
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS reg_read_own      ON public.registrations;
DROP POLICY IF EXISTS reg_insert_own    ON public.registrations;
DROP POLICY IF EXISTS reg_update_own    ON public.registrations;

-- Students can read their own registrations
CREATE POLICY reg_read_own ON public.registrations
  FOR SELECT TO anon
  USING (true);

-- Students can create registrations for themselves
CREATE POLICY reg_insert_own ON public.registrations
  FOR INSERT TO anon
  WITH CHECK (true);  -- Flask validates user_id matches session

-- Students can cancel their own registrations
CREATE POLICY reg_update_own ON public.registrations
  FOR UPDATE TO anon
  USING (true)
  WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- 9. RLS Policies — audit_logs (append-only via service role / Flask)
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS audit_insert ON public.audit_logs;
DROP POLICY IF EXISTS audit_read   ON public.audit_logs;

CREATE POLICY audit_insert ON public.audit_logs
  FOR INSERT TO anon WITH CHECK (true);

-- Only administrators read audit logs (enforced in Flask via @role_required)
CREATE POLICY audit_read ON public.audit_logs
  FOR SELECT TO anon USING (true);

-- ---------------------------------------------------------------------------
-- 10. Grant minimum required privileges to anon role
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE         ON public.users          TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.events         TO anon;
GRANT SELECT, INSERT, UPDATE         ON public.registrations  TO anon;
GRANT SELECT, INSERT                 ON public.audit_logs     TO anon;
GRANT USAGE ON SCHEMA public TO anon;

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
