-- Remote sessions (ticket #88): one per user per base while it lasts.
--
-- The path token itself lives only in the Portal's memory (single instance);
-- the database keeps its hash. A row with ended_at NULL is live; at startup
-- the Portal ends any it finds (its tunnels died with the old process).
CREATE TABLE remote_session (
    id                bigserial   PRIMARY KEY,
    account_id        bigint      NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    base_id           text        NOT NULL REFERENCES base (id) ON DELETE CASCADE,
    token_hash        bytea       NOT NULL UNIQUE,
    started_at        timestamptz NOT NULL,
    last_activity_at  timestamptz NOT NULL,
    ip                inet,
    ended_at          timestamptz,
    -- left (no Session bar for the idle timeout), hard_cap, portal_restart,
    -- or whatever revoked it (un-share, un-claim, log out everywhere, ...).
    end_reason        text
);
CREATE UNIQUE INDEX remote_session_live_idx
    ON remote_session (account_id, base_id) WHERE ended_at IS NULL;
CREATE INDEX remote_session_base_idx ON remote_session (base_id);
