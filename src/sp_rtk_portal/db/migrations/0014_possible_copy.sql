-- Possible copy (ticket #98).
--
-- Set the first time the base's key polls from two public IPs interleaved
-- within the window (A, B, A): when, and the two IPs. Never cleared: the
-- remedy for a cloned SD card is to Un-claim and Claim again (a new base,
-- a new key).
ALTER TABLE base
    ADD COLUMN possible_copy_at timestamptz,
    ADD COLUMN possible_copy_ips text[];
