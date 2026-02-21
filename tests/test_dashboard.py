import pytest

from detector.events import EventStore
from detector.analyzer import BehavioralAnalyzer
from dashboard.server import create_app


class _MockShadow:
    def verify_integrity(self):
        return {}


class _MockDaemon:
    def __init__(self, cfg):
        self.event_store = EventStore()
        self.analyzer = BehavioralAnalyzer(cfg, self.event_store)
        self.shadow = _MockShadow()

    def is_running(self):
        return True


@pytest.fixture
def client(mock_config):
    daemon = _MockDaemon(mock_config)
    app = create_app(daemon)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestDashboardRoutes:
    def test_index_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"RANSOMWARE DETECTION ENGINE" in resp.data

    def test_api_events_returns_json(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "events" in data
        assert "kill_decisions" in data
        assert "process_tree" in data

    def test_api_threat_returns_score(self, client):
        resp = client.get("/api/threat")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "score" in data
        assert "threshold" in data
        assert "max_possible" in data
        assert data["score"] == 0

    def test_api_status_returns_running(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["running"] is True

    def test_api_recent_returns_list(self, client):
        resp = client.get("/api/events/recent")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_api_reports_returns_list(self, client):
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_static_css_served(self, client):
        resp = client.get("/static/style.css")
        assert resp.status_code == 200

    def test_static_js_served(self, client):
        resp = client.get("/static/main.js")
        assert resp.status_code == 200
