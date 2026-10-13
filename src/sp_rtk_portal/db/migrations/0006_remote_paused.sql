-- Remote access paused on site (ticket #92): the base's agent reports
-- "paused" in each poll and ignores Wakes. Only the base can resume.
ALTER TABLE base
    ADD COLUMN remote_paused boolean NOT NULL DEFAULT false;
