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
    present = {o.dimensions["cve"]: o.value for o in obs}
    assert present == {"CVE-2026-109618": 1.0, "CVE-2026-109619": 0.0}

def test_isc_summary_three_metrics():
    obs = IscWebHoneypot.parse(_load("isc.json"))
    assert {o.metric for o in obs} == {"isc_reports", "isc_targets", "isc_sources"}
    assert next(o.value for o in obs if o.metric == "isc_reports") == 4200.0

def test_shodan_splits_fixed_vs_vulnerable():
    obs = ShodanExposure.parse(_load("shodan.json"))
    by = {o.metric: o.value for o in obs}
    assert by["php_hosts_vulnerable"] == 500000.0 and by["php_hosts_fixed"] == 200000.0
