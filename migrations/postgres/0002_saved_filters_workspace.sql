-- Saved filters become workspace-scoped, matching the SQLite repository.
ALTER TABLE saved_filters ADD COLUMN IF NOT EXISTS workspace TEXT NOT NULL DEFAULT 'default';
ALTER TABLE saved_filters DROP CONSTRAINT IF EXISTS saved_filters_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_filters_workspace_name ON saved_filters(workspace, name);
