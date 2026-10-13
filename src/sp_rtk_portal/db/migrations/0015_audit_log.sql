-- The audit log page (#99) finds an Operator's entries by base, and the
-- bases they Claimed (since Un-claimed) by their claim entries.
CREATE INDEX audit_entry_base_idx ON audit_entry (base_id, at);
CREATE INDEX audit_entry_claims_idx ON audit_entry (account_id) WHERE kind = 'claim';
