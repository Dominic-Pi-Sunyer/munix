import json
import shlex
import sys
from pathlib import Path

import pytest

from fake_smtp import FakeSmtp

HERE = Path(__file__).parent

CANNED_PAGE = {
    "url": "http://127.0.0.1:8080/reviews/gaming-monitor",
    "title": "UltraView 27 Gaming Monitor - Reviews",
    "page_type": "article",
    "headings": [{"level": 1, "text": "UltraView 27 Gaming Monitor"}, {"level": 2, "text": "Customer reviews"}],
    "navigation": [{"label": "Home", "url": "http://127.0.0.1:8080/", "location": "header"}],
    "content_links": {
        "total": 2,
        "truncated": False,
        "items": [
            {"label": "Specs", "url": "http://127.0.0.1:8080/specs"},
            {"label": "Home again", "url": "http://127.0.0.1:8080/"},
        ],
    },
    "tables": [{"id": "t", "headers": ["Port", "Count"], "rows": [["HDMI", "2"], ["DisplayPort", "1"]]}],
    "text_blocks": [
        {"tag": "p", "text": "Great panel, fast refresh."},
        {"tag": "p", "text": "Stand   is\nwobbly."},
    ],
}

EXPECTED_RENDER = "\n".join(
    [
        "Title: UltraView 27 Gaming Monitor - Reviews",
        "UltraView 27 Gaming Monitor",
        "Customer reviews",
        "Great panel, fast refresh.",
        "Stand is wobbly.",
        "Port | Count",
        "HDMI | 2",
        "DisplayPort | 1",
        "Links:",
        "http://127.0.0.1:8080/specs",
        "http://127.0.0.1:8080/",
    ]
)


@pytest.fixture
def smtp():
    server = FakeSmtp().start()
    yield server
    server.stop()


@pytest.fixture
def env(monkeypatch, smtp, tmp_path):
    page = tmp_path / "page.json"
    page.write_text(json.dumps(CANNED_PAGE))
    monkeypatch.setenv("MUNIX_SMTP", smtp.endpoint)
    monkeypatch.setenv(
        "WEBSPEED_COMMAND", " ".join(shlex.quote(a) for a in (sys.executable, str(HERE / "fake_webspeed.py"), str(page)))
    )
