CREATE TABLE threats (
    md5         VARCHAR(32) PRIMARY KEY CHECK (md5 ~ '^[a-fA-F0-9]{32}$'),
    name        VARCHAR(255) NOT NULL CHECK (length(trim(name)) > 0),
    category    VARCHAR(32) NOT NULL DEFAULT 'unknown',
    severity    VARCHAR(16) NOT NULL DEFAULT 'unknown',
    description VARCHAR(4000) NOT NULL DEFAULT '',
    family      VARCHAR(255) NOT NULL DEFAULT '',
    confidence  SMALLINT NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    source      VARCHAR(255) NOT NULL DEFAULT '',
    tags        TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX threats_category_idx ON threats(category);
CREATE INDEX threats_severity_idx ON threats(severity);
CREATE INDEX threats_updated_at_idx ON threats(updated_at DESC);
