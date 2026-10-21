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
