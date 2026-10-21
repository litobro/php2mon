from php2mon.feeds.__main__ import build_collectors
from php2mon.feeds.settings import Settings


def test_settings_all_present():
    s = Settings.from_env({"DATABASE_URL": "pg://x", "CONTACT_EMAIL": "a@b", "CF_RADAR_TOKEN": "t",
                           "SHODAN_API_KEY": "k", "GEOIP_DIR": "/g"})
    assert (s.database_url, s.contact_email, s.cf_radar_token, s.shodan_api_key, s.geoip_dir) == ("pg://x", "a@b", "t", "k", "/g")


def test_settings_absent_and_empty_are_none_and_default_dir():
    s = Settings.from_env({"DATABASE_URL": "pg://x", "CF_RADAR_TOKEN": "", "GEOIP_DIR": ""})
    assert s.cf_radar_token is None and s.shodan_api_key is None and s.contact_email is None
    assert s.geoip_dir == "/geoip"


def _names(env):
    return {c.name for c in build_collectors(Settings.from_env({"DATABASE_URL": "x", **env}))}


def test_collector_selection():
    base = _names({})
    assert "geoip_refresh" in base and len(base) == 3
    both = _names({"CF_RADAR_TOKEN": "t", "SHODAN_API_KEY": "k"})
    assert len(both) == 5 and base < both
    assert len(_names({"CF_RADAR_TOKEN": "t"})) == 4
    assert len(_names({"SHODAN_API_KEY": "k"})) == 4
