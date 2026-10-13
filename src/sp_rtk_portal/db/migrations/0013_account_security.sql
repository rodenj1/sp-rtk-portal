-- Account security (ticket #96).
--
-- ``share_review_due``: a password change or recovery happened and the user
-- hasn't yet marked the review of recent Shares as seen; every login lands
-- on the review page until they do.
ALTER TABLE account ADD COLUMN share_review_due boolean NOT NULL DEFAULT false;

-- ``deleted_at``: the user deleted their account. The row stays so the audit
-- log keeps saying who did what (its entries reference it); its bases,
-- Shares and sessions are gone and the Authentik user is deactivated. A
-- login (only possible if an admin reactivates the Authentik user) clears it.
ALTER TABLE account ADD COLUMN deleted_at timestamptz;
