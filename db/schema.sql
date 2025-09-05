-- PostgreSQL schema for Vigil

CREATE TABLE IF NOT EXISTS plugins (
    id SERIAL PRIMARY KEY,
    plugin_name VARCHAR(255) NOT NULL,
    upload_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(50) NOT NULL,
    source_location TEXT NOT NULL,
    scan_status VARCHAR(50) DEFAULT 'PENDING'
);

CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    plugin_id INTEGER NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    severity VARCHAR(50) NOT NULL,
    vulnerability_id VARCHAR(100),
    vulnerability_name TEXT NOT NULL,
    cvss_score NUMERIC(3,1),
    description TEXT,
    fix_suggestion TEXT,
    ai_suggestion TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_results_plugin_id ON scan_results(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugins_scan_status ON plugins(scan_status);


