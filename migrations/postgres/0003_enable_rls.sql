-- Block Supabase's public PostgREST/anon roles from every SOAR table.
-- With RLS on and no policies, only roles that bypass RLS (table owner, `postgres`,
-- service_role) can read or write. The SOAR backend connects as the owner/`postgres`,
-- so it is unaffected. Do NOT connect the backend as a non-bypass role after this.
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE queue_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_filters ENABLE ROW LEVEL SECURITY;
