import json
from pathlib import Path
from php2mon.feeds.sources import IscWebHoneypot, CloudflareRadar, CisaKev, ShodanExposure

FIX = Path(__file__).parent / "fixtures"
def _load(n): return json.loads((FIX / n).read_text())

def test_radar_parses_timeseries():
    obs = CloudflareRadar.parse(_load("radar.json"))
    assert {o.ts.hour: o.value for o in obs} == {14: 1.5, 15: 2.5}
    assert all(o.metric == "l7_attacks" for o in obs)

def test_kev_flags_target_cves_only():
    obs = CisaKev.parse(_load("kev.json"))
    present = {o.dimensions["cve"]: o.value for o in obs if o.metric == "kev_listed"}
    assert present == {"CVE-2026-109618": 1.0, "CVE-2026-109619": 0.0}

def test_isc_summary_three_metrics():
    obs = IscWebHoneypot.parse(_load("isc.json"))
    assert {o.metric for o in obs} == {"isc_records", "isc_targets", "isc_sources"}
    assert next(o.value for o in obs if o.metric == "isc_records") == 25948539.0
    assert all(o.ts.year == 2026 and o.ts.month == 10 and o.ts.day == 20 for o in obs)

def test_shodan_splits_fixed_vs_vulnerable():
    obs = ShodanExposure.parse(_load("shodan.json"))
    by = {o.metric: o.value for o in obs}
    assert by["php_hosts_vulnerable"] == 500000.0 and by["php_hosts_fixed"] == 200000.0


import asyncio
from types import SimpleNamespace
import pytest
from php2mon.feeds.sources import _scrub, is_fixed


def test_scrub_redacts_shodan_key():
    assert _scrub("...key=abc123&facets=x") == "...key=REDACTED&facets=x"
    assert _scrub("GET https://x/?key=abc123") == "GET https://x/?key=REDACTED"


@pytest.mark.parametrize("v,want", [
    ("7.4.33", False), ("8.1", False), ("8.2.35", True), ("8.2.28", False),
    ("8.6.0", True), ("8.2.35-1ubuntu", True), ("8.3.0RC1", False), ("", None),
])
def test_is_fixed(v, want):
    assert is_fixed(v) is want


def test_shodan_counts_short_versions_as_vulnerable():
    p = {"facets": {"version": [{"count": 5, "value": "7.4"}, {"count": 1, "value": ""},
                                {"count": 2, "value": "8.6.0"}, {"value": "8.2.1"}]}, "total": 9}
    by = {o.metric: o.value for o in ShodanExposure.parse(p)}
    assert by == {"php_hosts_fixed": 2.0, "php_hosts_vulnerable": 5.0, "php_hosts_total": 9.0}


def test_shodan_missing_facets():
    assert {o.metric: o.value for o in ShodanExposure.parse({"facets": None})}["php_hosts_total"] == 0.0


def test_kev_both_present_stable_dims():
    p = {"vulnerabilities": [{"cveID": "CVE-2026-109618", "dateAdded": "2026-10-21"},
                             {"cveID": "CVE-2026-109619", "dateAdded": "2026-10-22"}]}
    obs = CisaKev.parse(p)
    listed = [o for o in obs if o.metric == "kev_listed"]
    assert [(o.dimensions, o.value) for o in listed] == [
        ({"cve": "CVE-2026-109618"}, 1.0), ({"cve": "CVE-2026-109619"}, 1.0)]
    dates = [o for o in obs if o.metric == "kev_date_added_epoch"]
    assert len(dates) == 2 and all(set(o.dimensions) == {"cve"} for o in dates)


def test_kev_absent_cve_yields_zero_row():
    obs = CisaKev.parse(_load("kev.json"))
    absent = [o for o in obs if o.dimensions == {"cve": "CVE-2026-109619"}]
    assert len(absent) == 1 and absent[0].metric == "kev_listed" and absent[0].value == 0.0


def test_radar_empty_and_null_values():
    assert CloudflareRadar.parse({"result": {"serie_0": {"timestamps": [], "values": []}}}) == []
    assert CloudflareRadar.parse({"result": {}}) == []
    p = {"result": {"serie_0": {"timestamps": ["2026-10-21T14:00:00Z", "2026-10-21T15:00:00Z"], "values": [None, "1"]}}}
    assert [o.value for o in CloudflareRadar.parse(p)] == [1.0]


def test_isc_list_shape_and_empty():
    p = [{"date": "2026-10-20", "records": "1", "targets": "2", "sources": "3"}]
    assert len(IscWebHoneypot.parse(p)) == 3
    assert IscWebHoneypot.parse([]) == []
    assert IscWebHoneypot.parse({}) == []
    assert IscWebHoneypot.parse([{"date": "2026-10-20"}]) == []


def test_disabled_without_credentials(monkeypatch):
    monkeypatch.delenv("CF_RADAR_TOKEN", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    ctx = SimpleNamespace(settings=None)
    assert asyncio.run(CloudflareRadar().collect(ctx)) == []
    assert asyncio.run(ShodanExposure().collect(ctx)) == []
