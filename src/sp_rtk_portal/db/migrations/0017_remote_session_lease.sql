-- Leased path tokens (ADR 0005, ticket #202): when a Remote session's path
-- token stops working unless its Session bar renews it. Each renewal moves
-- it on; the session ends (end_reason 'lease_expired') once it passes. NULL
-- on sessions from before leases.
ALTER TABLE remote_session ADD COLUMN lease_expires_at timestamptz;
