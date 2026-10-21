import httpx
import pytest

from php2mon.feeds.client import FeedResult, fetch_json


async def test_fetch_json_success(httpx_mock):
    httpx_mock.add_response(url="https://x.test/a", json={"k": 1})
    async with httpx.AsyncClient() as c:
        r = await fetch_json(c, "https://x.test/a")
    assert r.ok and r.json == {"k": 1} and r.status == 200


async def test_fetch_json_http_error_not_raised(httpx_mock):
    httpx_mock.add_response(url="https://x.test/b", status_code=500, text="boom")
    async with httpx.AsyncClient() as c:
        r = await fetch_json(c, "https://x.test/b")
    assert not r.ok and r.status == 500 and r.error


async def test_fetch_json_timeout_not_raised(httpx_mock):
    httpx_mock.add_exception(httpx.ReadTimeout("slow"))
    async with httpx.AsyncClient() as c:
        r = await fetch_json(c, "https://x.test/c", timeout=0.01)
    assert not r.ok and r.status is None and "slow" in r.error


async def test_fetch_json_bad_json_not_raised(httpx_mock):
    httpx_mock.add_response(url="https://x.test/d", text="not json", headers={"content-type": "application/json"})
    async with httpx.AsyncClient() as c:
        r = await fetch_json(c, "https://x.test/d")
    assert not r.ok and r.text == "not json" and r.error
