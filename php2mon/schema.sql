CREATE TABLE IF NOT EXISTS sensor_hits (
    id              bigserial PRIMARY KEY,
    ts              timestamptz NOT NULL,
    src_ip          inet NOT NULL,
    country         text,
    asn             bigint,
    asn_name        text,
    method          text NOT NULL,
    path            text NOT NULL,
    host            text,
    user_agent      text,
    content_type    text,
    body_bytes      bigint NOT NULL,
    multipart_parts integer NOT NULL,
    sess_len        integer NOT NULL,
    resp_status     integer NOT NULL,
    signatures      text[] NOT NULL DEFAULT '{}',
    detail          jsonb
);
CREATE INDEX IF NOT EXISTS sensor_hits_ts_idx ON sensor_hits (ts);
CREATE INDEX IF NOT EXISTS sensor_hits_src_ts_idx ON sensor_hits (src_ip, ts);

CREATE TABLE IF NOT EXISTS feed_observations (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL,
    source      text NOT NULL,
    metric      text NOT NULL,
    dimensions  jsonb NOT NULL DEFAULT '{}',
    value       double precision NOT NULL
);
CREATE INDEX IF NOT EXISTS feed_observations_idx ON feed_observations (source, metric, ts);

CREATE TABLE IF NOT EXISTS feed_raw (
    id      bigserial PRIMARY KEY,
    ts      timestamptz NOT NULL,
    source  text NOT NULL,
    payload jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_status (
    source                text PRIMARY KEY,
    last_ok               timestamptz,
    last_error            text,
    consecutive_failures  integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS claims (
    id     bigserial PRIMARY KEY,
    ts     timestamptz NOT NULL,
    org    text NOT NULL,
    claim  text NOT NULL,
    url    text
);
