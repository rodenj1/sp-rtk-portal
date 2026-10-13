-- The Doorbell (ticket #100, ADR 0002).
--
-- ring_key: the base's ring key (base64url, 256 bits), made at its first
-- Check-in while the agent config names a Doorbell host and handed to the
-- agent in Check-in replies; rings are authenticated with it.
-- last_doorbell_at: the latest keepalive the Doorbell server relayed (also a
-- sign of life: last_seen_at moves with it).
ALTER TABLE base
    ADD COLUMN ring_key text,
    ADD COLUMN last_doorbell_at timestamptz;
