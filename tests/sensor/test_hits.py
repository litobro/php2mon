from datetime import datetime, timezone

from php2mon.sensor.hits import (
    BODY_HEAD_CAP,
    HEADER_VALUE_CAP,
    MultipartCounter,
    build_hit,
    session_length,
)


def test_session_length_reads_named_cookie():
    assert session_length("a=1; PHPSESSID=abcdef; b=2", "PHPSESSID") == 6


def test_session_length_handles_malformed_cookies():
    assert session_length(None, "PHPSESSID") == 0
    assert session_length("garbage", "PHPSESSID") == 0
    assert session_length("PHPSESSID=", "PHPSESSID") == 0
    assert session_length("PHPSESSID=x; PHPSESSID=yyyy", "PHPSESSID") == 1


def test_multipart_counter_counts_parts_across_chunks():
    boundary = "----WebKitFormBoundaryAbc"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    counter = MultipartCounter.from_content_type(
        f"multipart/form-data; boundary={boundary}"
    )
    assert counter is not None
    for i in range(0, len(body), 7):
        counter.feed(body[i : i + 7])
    assert counter.parts == 2


def test_multipart_counter_none_without_boundary():
    assert MultipartCounter.from_content_type("multipart/form-data") is None
    assert MultipartCounter.from_content_type("application/json") is None
    assert MultipartCounter.from_content_type(None) is None


def test_build_hit_normalises_and_caps_headers():
    now = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)
    hit = build_hit(
        src_ip="203.0.113.9",
        method="post",
        path="/wp-login.php",
        headers=[
            ("Host", "example.test"),
            ("User-Agent", "curl/8"),
            ("Content-Type", "multipart/form-data; boundary=x"),
            ("Cookie", "PHPSESSID=" + "a" * 300),
            ("X-Big", "z" * 100_000),
        ],
        body_bytes=12,
        multipart_parts=1,
        body_head=b"x" * (BODY_HEAD_CAP + 50),
        now=now,
    )
    assert hit.ts == now
    assert hit.method == "POST"
    assert hit.host == "example.test"
    assert hit.user_agent == "curl/8"
    assert hit.content_type.startswith("multipart/form-data")
    assert hit.sess_len == 300
    assert hit.header_names == ["host", "user-agent", "content-type", "cookie", "x-big"]
    assert len(hit.headers["x-big"]) == HEADER_VALUE_CAP
    assert len(hit.body_head) == BODY_HEAD_CAP
    assert hit.resp_status == 0
    assert hit.signatures == []
    assert hit.detail_kept is True


def test_to_detail_is_json_safe():
    import json

    hit = build_hit(
        src_ip="203.0.113.9",
        method="GET",
        path="/",
        headers=[("Host", "h")],
        body_bytes=3,
        multipart_parts=0,
        body_head=b"\xff\xfe\x00",
    )
    text = json.dumps(hit.to_detail())
    assert "headers" in text and "body_head" in text


def test_sess_len_measured_before_header_truncation():
    hit = build_hit(
        src_ip="203.0.113.9",
        method="GET",
        path="/",
        headers=[("Cookie", "a=1; PHPSESSID=" + "s" * 5000)],
        body_bytes=0,
        multipart_parts=0,
        body_head=b"",
    )
    assert hit.sess_len == 5000
    assert len(hit.headers["cookie"]) == HEADER_VALUE_CAP
