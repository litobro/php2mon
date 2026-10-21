from php2mon.sensor.geoip import GeoLookup
from php2mon.sensor.hits import build_hit


def _hit(ip="203.0.113.5"):
    return build_hit(src_ip=ip, method="GET", path="/", headers=[], body_bytes=0, multipart_parts=0, body_head=b"")


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get(self, ip):
        return self.data.get(ip)


def test_enrich_fills_country_and_asn():
    geo = GeoLookup(
        country_reader=FakeReader({"203.0.113.5": {"country": {"iso_code": "NL"}}}),
        asn_reader=FakeReader(
            {"203.0.113.5": {"autonomous_system_number": 64500, "autonomous_system_organization": "EXAMPLE-AS"}}
        ),
    )
    hit = _hit()
    geo.enrich(hit)
    assert (hit.country, hit.asn, hit.asn_name) == ("NL", 64500, "EXAMPLE-AS")


def test_enrich_without_readers_or_records_is_noop():
    hit = _hit()
    GeoLookup().enrich(hit)
    GeoLookup(country_reader=FakeReader({})).enrich(hit)
    assert (hit.country, hit.asn, hit.asn_name) == (None, None, None)


def test_enrich_swallows_reader_errors():
    class Boom:
        def get(self, ip):
            raise ValueError("bad ip")

    hit = _hit("not-an-ip")
    GeoLookup(country_reader=Boom()).enrich(hit)
    assert hit.country is None


def test_from_dir_with_missing_files(tmp_path):
    geo = GeoLookup.from_dir(tmp_path)
    hit = _hit()
    geo.enrich(hit)
    assert hit.country is None
