-- Account security (ticket #96).
--
-- ``share_review_due``: a password change or recovery happened and the user
-- hasn't yet marked the review of recent Shares as seen; every login lands
-- on the review page until they do.
ALTER TABLE account ADD COLUMN share_review_due boolean NOT NULL DEFAULT false;
