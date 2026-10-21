from php2mon.sensor.ratelimit import RateLimiter


def test_allows_up_to_limit_then_denies_until_window_rolls():
    now = [0.0]
    rl = RateLimiter(per_minute=3, clock=lambda: now[0])
    assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("b") is True
    now[0] += 60
    assert rl.allow("a") is True


def test_prune_drops_stale_buckets():
    now = [0.0]
    rl = RateLimiter(per_minute=1, clock=lambda: now[0])
    for i in range(5):
        rl.allow(f"ip{i}")
    now[0] += 120
    rl._prune(now[0])
    assert rl._buckets == {}


def test_ipv6_keyed_by_64(monkeypatch):
    rl = RateLimiter(per_minute=1, clock=lambda: 0.0)
    assert rl.allow("2001:db8::1") is True
    assert rl.allow("2001:db8::2") is False
    assert rl.allow("2001:db8:1::1") is True


def test_bucket_cap_evicts_oldest(monkeypatch):
    monkeypatch.setattr("php2mon.sensor.ratelimit.MAX_BUCKETS", 3)
    rl = RateLimiter(per_minute=1, clock=lambda: 0.0)
    for i in range(4):
        rl.allow(f"ip{i}")
    assert len(rl._buckets) == 3
    assert "ip0" not in rl._buckets
    assert rl.allow("ip0") is True


def test_prune_runs_via_allow():
    now = [0.0]
    rl = RateLimiter(per_minute=1, clock=lambda: now[0])
    for i in range(5):
        rl.allow(f"ip{i}")
    rl._calls = 9_999
    now[0] = 120.0
    rl.allow("fresh")
    assert rl._buckets.keys() == {"fresh"}


def test_ipv4_mapped_keys_as_ipv4():
    rl = RateLimiter(per_minute=1, clock=lambda: 0.0)
    assert rl.allow("::ffff:1.2.3.4") is True
    assert rl.allow("1.2.3.4") is False
    assert rl.allow("::ffff:1.2.3.5") is True


def test_scoped_ipv6_does_not_raise():
    rl = RateLimiter(per_minute=1, clock=lambda: 0.0)
    assert rl.allow("fe80::1%eth0") is True
