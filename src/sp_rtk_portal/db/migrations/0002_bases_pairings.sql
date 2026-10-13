-- Claimed bases and the pairings (RFC 8628) that Claim them.

-- A Claimed base. The Portal holds only its public key (a JWK) and finds it
-- by the key's RFC 7638 thumbprint. Re-Claiming makes a new row and id.
CREATE TABLE base (
    id                text        PRIMARY KEY,
    public_key        jsonb       NOT NULL,
    key_thumbprint    text        NOT NULL UNIQUE,
    name              text        NOT NULL,
    owner_account_id  bigint      NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    claimed_at        timestamptz NOT NULL,
    software_version  text        NOT NULL DEFAULT '',
    protocol_version  integer     NOT NULL,
    last_seen_at      timestamptz
);
CREATE INDEX base_owner_idx ON base (owner_account_id);

-- A Claim in progress: an agent asked for a code and polls for the result.
-- Only a hash of the device code is stored.
CREATE TABLE pairing (
    device_code_hash  bytea       PRIMARY KEY,
    user_code         text        NOT NULL UNIQUE,
    public_key        jsonb       NOT NULL,
    key_thumbprint    text        NOT NULL,
    suggested_name    text        NOT NULL,
    software_version  text        NOT NULL,
    protocol_version  integer     NOT NULL,
    ip                inet,
    requested_at      timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    last_polled_at    timestamptz,
    -- Set when an Operator approves it.
    base_id           text        REFERENCES base (id) ON DELETE CASCADE
);
CREATE INDEX pairing_expires_idx ON pairing (expires_at);
