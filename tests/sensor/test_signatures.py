from pathlib import Path

import pytest
from pydantic import ValidationError

from php2mon.sensor.hits import build_hit
from php2mon.sensor.signatures import Confidence, Evaluator, RuleSet, load_rules

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example" / "signatures.yaml"


def _hit(**kw):
    base = dict(
        src_ip="203.0.113.1",
        method="GET",
        path="/",
        headers=[],
        body_bytes=0,
        multipart_parts=0,
        body_head=b"",
    )
    base.update(kw)
    return build_hit(**base)


def _ruleset(*rules):
    return RuleSet.model_validate({"rules": list(rules)})


def test_example_rules_load_with_valid_confidences():
    rs = load_rules(EXAMPLE)
    assert rs.rules
    assert all(r.confidence in Confidence for r in rs.rules)


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        _ruleset({"id": "x", "label": "x", "confidence": "maybe", "when": {}})


def test_static_conditions_all_must_match():
    ev = Evaluator(
        _ruleset(
            {
                "id": "mp",
                "label": "big multipart",
                "confidence": "likely",
                "when": {
                    "method": "POST",
                    "content_type_prefix": "multipart/form-data",
                    "body_bytes_min": 1000,
                },
            }
        )
    )
    yes = _hit(
        method="POST",
        headers=[("Content-Type", "multipart/form-data; boundary=a")],
        body_bytes=1000,
    )
    no = _hit(
        method="POST",
        headers=[("Content-Type", "multipart/form-data; boundary=a")],
        body_bytes=999,
    )
    assert ev.evaluate(yes) == ["mp"]
    assert ev.evaluate(no) == []


def test_path_and_header_conditions():
    ev = Evaluator(
        _ruleset(
            {"id": "p1", "label": "", "confidence": "probe", "when": {"path_prefix": "/wp-"}},
            {"id": "p2", "label": "", "confidence": "probe", "when": {"path_contains": ".php"}},
            {"id": "h", "label": "", "confidence": "probe", "when": {"header_present": "X-Forwarded-For"}},
            {"id": "ua", "label": "", "confidence": "probe", "when": {"user_agent_contains": "zgrab"}},
            {"id": "s", "label": "", "confidence": "likely", "when": {"sess_len_min": 100}},
        )
    )
    hit = _hit(
        path="/wp-login.php",
        headers=[
            ("x-forwarded-for", "1.1.1.1"),
            ("User-Agent", "Mozilla zgrab/0.x"),
            ("Cookie", "PHPSESSID=" + "a" * 100),
        ],
    )
    assert ev.evaluate(hit) == ["p1", "p2", "h", "ua", "s"]


def test_repeat_rule_counts_within_window_per_ip():
    now = [1000.0]
    ev = Evaluator(
        _ruleset(
            {
                "id": "rep",
                "label": "",
                "confidence": "exploit",
                "when": {"resp_status": 500, "repeats_min": 3, "window_seconds": 60},
            }
        ),
        clock=lambda: now[0],
    )
    a = _hit(src_ip="203.0.113.1")
    a.resp_status = 500
    b = _hit(src_ip="203.0.113.2")
    b.resp_status = 500
    assert ev.evaluate(a) == []
    assert ev.evaluate(a) == []
    assert ev.evaluate(b) == []
    assert ev.evaluate(a) == ["rep"]
    now[0] += 61
    assert ev.evaluate(a) == []


def test_replace_rules_keeps_repeat_history():
    now = [0.0]
    rule = {
        "id": "rep",
        "label": "",
        "confidence": "exploit",
        "when": {"repeats_min": 2, "window_seconds": 60},
    }
    ev = Evaluator(_ruleset(rule), clock=lambda: now[0])
    hit = _hit()
    assert ev.evaluate(hit) == []
    ev.replace_rules(_ruleset(rule))
    assert ev.evaluate(hit) == ["rep"]
