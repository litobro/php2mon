from pathlib import Path

from fastapi import FastAPI

from php2mon.web import app as webapp


def test_factory_entrypoint_and_static_assets():
    # docker/dashboard.Dockerfile runs `uvicorn --factory php2mon.web.app:create_app`
    assert isinstance(webapp.create_app("postgresql://x@localhost/x"), FastAPI)
    assert (Path(webapp.__file__).parent / "static" / "chart.umd.min.js").is_file()
