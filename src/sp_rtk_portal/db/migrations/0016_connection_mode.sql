-- How the Portal reaches a base (ADR 0006, ticket #204): through the tunnel
-- it holds open ('holding'), not now because that tunnel dropped and hasn't
-- come back yet ('reconnecting'), or only by Waking it through its polls
-- ('polling', every base before held tunnels). Offline isn't stored: it
-- follows from last_seen_at.
ALTER TABLE base
    ADD COLUMN connection_mode text NOT NULL DEFAULT 'polling'
        CHECK (connection_mode IN ('holding', 'reconnecting', 'polling'));
