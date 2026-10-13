-- Portal accounts, Portal sessions and the audit log.

CREATE TABLE account (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    iss             text        NOT NULL,
    sub             text        NOT NULL,
    email           text        NOT NULL,
    email_verified  boolean     NOT NULL,
    created_at      timestamptz NOT NULL,
    last_login_at   timestamptz NOT NULL,
    UNIQUE (iss, sub)
);

-- A Portal session. Only a hash of the cookie value is stored.
CREATE TABLE portal_session (
    token_hash    bytea       PRIMARY KEY,
    account_id    bigint      NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL,
    last_used_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL
);
CREATE INDEX portal_session_account_idx ON portal_session (account_id);

CREATE TABLE audit_entry (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL,
    kind        text        NOT NULL,
    account_id  bigint      REFERENCES account (id) ON DELETE SET NULL,
    base_id     text,
    ip          inet,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_entry_at_idx ON audit_entry (at);
CREATE INDEX audit_entry_account_idx ON audit_entry (account_id);
