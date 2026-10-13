-- Shares and Pending shares (ticket #94).
--
-- A Share gives one account full remote access to one base (but not re-Share
-- or Un-claim). Both go with the base (Un-claim) and with the account.
-- ``created_by`` is whoever made it (the Operator), kept for the review page
-- after a password change (#96).
CREATE TABLE share (
    base_id     text        NOT NULL REFERENCES base (id) ON DELETE CASCADE,
    account_id  bigint      NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL,
    created_by  bigint      REFERENCES account (id) ON DELETE SET NULL,
    PRIMARY KEY (base_id, account_id)
);
CREATE INDEX share_account_idx ON share (account_id);
CREATE INDEX share_created_by_idx ON share (created_by, created_at);

-- A Share waiting for its recipient: converts into a Share on the first
-- login of an account with this verified email before ``expires_at``.
-- ``email`` is stored lowercased.
CREATE TABLE pending_share (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    base_id     text        NOT NULL REFERENCES base (id) ON DELETE CASCADE,
    email       text        NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_by  bigint      REFERENCES account (id) ON DELETE SET NULL,
    UNIQUE (base_id, email)
);
CREATE INDEX pending_share_email_idx ON pending_share (email);
CREATE INDEX pending_share_created_by_idx ON pending_share (created_by, created_at);
