-- Polls, Check-ins and the agent config (ticket #87, ADR 0002).

-- What a base's polls and Check-ins tell the Portal. Online state is derived
-- from last_seen_at and the poll interval of its current mode.
ALTER TABLE base
    -- The Operator marked the base metered: it polls less often.
    ADD COLUMN metered          boolean     NOT NULL DEFAULT false,
    -- The metered flag the base was last told: it may still sleep the
    -- metered interval after the Operator unmarks it.
    ADD COLUMN polled_metered   boolean     NOT NULL DEFAULT false,
    -- [{address, interface, primary}], from the latest Check-in.
    ADD COLUMN lan_addresses    jsonb       NOT NULL DEFAULT '[]',
    ADD COLUMN public_ip        inet,
    -- Doorbell health from the latest Check-in (off, ignored, unavailable, ok).
    ADD COLUMN doorbell         text        NOT NULL DEFAULT 'off',
    -- Its last request was refused with 426 (protocol too old).
    ADD COLUMN needs_upgrade    boolean     NOT NULL DEFAULT false,
    ADD COLUMN last_check_in_at timestamptz;

-- Every revision of the agent config block the Portal owner saved; the
-- highest is current. No row: the built-in defaults as revision 1.
CREATE TABLE agent_config (
    revision    integer     PRIMARY KEY,
    config      jsonb       NOT NULL,
    created_at  timestamptz NOT NULL,
    created_by  bigint      REFERENCES account (id) ON DELETE SET NULL
);

-- Notices for every base (e.g. a deprecation date): sent in every poll and
-- Check-in reply and shown on each base in the list.
CREATE TABLE notice (
    id          bigserial   PRIMARY KEY,
    text        text        NOT NULL,
    created_at  timestamptz NOT NULL
);

-- Small Portal-wide values the Portal owner sets (latest_release).
CREATE TABLE portal_setting (
    key         text        PRIMARY KEY,
    value       text        NOT NULL
);
