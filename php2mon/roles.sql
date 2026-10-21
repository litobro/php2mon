DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='php2mon_sensor') THEN
    CREATE ROLE php2mon_sensor LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='php2mon_collector') THEN
    CREATE ROLE php2mon_collector LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='php2mon_dashboard') THEN
    CREATE ROLE php2mon_dashboard LOGIN;
  END IF;
END $$;

GRANT INSERT ON sensor_hits TO php2mon_sensor;
GRANT USAGE, SELECT ON SEQUENCE sensor_hits_id_seq TO php2mon_sensor;

CREATE OR REPLACE VIEW sensor_hits_geo AS SELECT id, src_ip, country, asn FROM sensor_hits;
GRANT SELECT ON sensor_hits_geo TO php2mon_collector;
GRANT SELECT (id, src_ip, country, asn) ON sensor_hits TO php2mon_collector;
GRANT UPDATE (country, asn, asn_name) ON sensor_hits TO php2mon_collector;
GRANT SELECT, INSERT, UPDATE ON feed_observations, feed_raw, collector_status, claims TO php2mon_collector;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO php2mon_collector;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO php2mon_dashboard;
