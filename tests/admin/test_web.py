# Test for admin/web.py
# Created by Gemini using model gemini-1.5-pro-001 on 2026-02-05
# Modified by Gemini using model gemini-1.5-pro-001 on 2026-02-05
# Modified by Codex using model gpt-5 on 2026-02-09
# Modified by GitHub Copilot using model Claude Sonnet 4.5 on 2026-02-11
"""
Unit tests for the admin/web.py module.

This test suite covers:
- Web page rendering (admin UI pages, DNS logs, tuning pages)
- Data API endpoints for alerts, DNS domains/queries, and network/host configuration
- Webhook handling for receiving alerts from DNS listener and OpenCanary
- Database operations via sql_action helper
- Home Assistant integration (notifications and webhooks)
- Helper functions for request parsing and URL generation

The tests use pytest and pytest-twisted for testing the Twisted-based web server.
Dummy classes simulate HTTP requests and responses without requiring a running server.
"""

import admin.web as web
import json
from types import SimpleNamespace


# ============================================================================
# Mock/Dummy Classes for Testing
# ============================================================================
# These classes simulate Twisted web server components without needing a
# running server, allowing isolated testing of request/response logic.


class DummyPeer:
    """Mock peer object representing the remote client's network address."""
    def __init__(self, host):
        self.host = host


class DummyTransport:
    """Mock transport layer that provides peer connection information."""
    def __init__(self, host):
        self._host = host

    def getPeer(self):
        """Return the peer address for the connection."""
        return DummyPeer(self._host)


class DummyContent:
    """Mock content object for request body data."""
    def __init__(self, data=b""):
        self._data = data

    def getvalue(self):
        """Return the request body content as bytes."""
        return self._data


class DummyRequest:
    """
    Mock HTTP request object that simulates Twisted's Request interface.
    
    Args:
        args: Query string parameters as a dict of bytes to list of bytes
        url: The request URL
        ingress: The X-Ingress-Path header value (for Home Assistant ingress support)
        content: Request body as bytes (for POST data)
        peer_host: IP address of the client making the request
    """
    def __init__(self, args=None, url="http://example.com/admin", ingress=None, content=b"", peer_host="127.0.0.1"):
        self.args = args or {}
        self._url = url
        self._ingress = ingress
        self.headers = {}
        self.content = DummyContent(content)
        self.transport = DummyTransport(peer_host)

    def getHeader(self, name):
        """Get a request header value."""
        if name == "X-Ingress-Path":
            return self._ingress
        return None

    def URLPath(self):
        """Return the request URL."""
        return self._url

    def setHeader(self, name, value):
        """Set a response header."""
        self.headers[name] = value


class DummyResponse:
    """Mock HTTP response object for simulating responses from external services."""
    def __init__(self, status_code=200, content=b"ok"):
        self.status_code = status_code
        self.content = content


# ============================================================================
# Test Helper Functions
# ============================================================================


def setup_data_db(tmp_path, monkeypatch):
    """
    Initialize a test database with the required schema.
    
    Creates all necessary tables and views in a temporary SQLite database:
    - alerts: Stores security alerts from DNS and honeypot
    - domains: Tracks DNS domains and their access patterns
    - queries: Logs individual DNS queries
    - networks: Defines network scopes for monitoring
    - hosts: Stores known hosts within monitored networks
    - Views for joining related data
    
    Args:
        tmp_path: Pytest fixture providing a temporary directory
        monkeypatch: Pytest fixture for modifying module attributes
    """
    monkeypatch.setattr(web, "CONFIG_DB_PATH", str(tmp_path))
    monkeypatch.setattr(web, "CONFIG_DB_NAME", "test.db")

    web.sql_action(
        f'CREATE TABLE "{web.DB_T_ALERTS}" ("id" TEXT, "timestamp" TEXT, "type" TEXT, "src_ip" TEXT, "message" TEXT, "unread" INTEGER)',
        (),
    )
    web.sql_action(
        f'CREATE TABLE "{web.DB_T_DOMAINS}" ("id" TEXT, "domain" TEXT, "counter" INTEGER, "scope" TEXT, "action" TEXT, "last_seen" TEXT, "alert" INTEGER DEFAULT 1)',
        (),
    )
    web.sql_action(
        f'CREATE TABLE "{web.DB_T_QUERIES}" ("id" TEXT, "src" TEXT, "scope_id" TEXT, "query" TEXT, "query_type" TEXT, "counter" INTEGER, "action" TEXT, "last_seen" TEXT, "domain_id" TEXT, "alert" INTEGER DEFAULT 1)',
        (),
    )
    web.sql_action(
        f'CREATE TABLE "{web.DB_T_NETWORKS}" ("id" TEXT, "ip" TEXT, "type" TEXT, "action" TEXT, "created" TEXT, "name" TEXT)',
        (),
    )
    web.sql_action(
        f'CREATE TABLE "{web.DB_T_HOSTS}" ("id" TEXT, "ip" TEXT, "scope_id" TEXT, "name" TEXT)',
        (),
    )
    web.sql_action(web.DB_SCHEMA_V_DOMAINS, ())
    web.sql_action(web.DB_SCHEMA_V_QUERIES, ())
    web.sql_action(web.DB_SCHEMA_V_DNS_IGNORED, ())


# ============================================================================
# Tests for Web Page Rendering
# ============================================================================


def test_webroot_page_render_get():
    """Test that the root page renders with expected content."""
    page = web.WebRootPage()
    output = page.render_GET(DummyRequest())
    assert b"There is no spoon" in output


def test_webroot_get_child_returns_page():
    """Test that the root returns a WebRootPage for any path."""
    root = web.WebRoot()
    child = root.getChild(b"anything", DummyRequest())
    assert isinstance(child, web.WebRootPage)


def test_admin_page_render_get():
    """Test that the admin alerts page renders with the correct title and API endpoint."""
    page = web.AdminPage()
    output = page.render_GET(DummyRequest(url="http://example.com/admin"))
    assert b"Home Detector -> Alerts" in output
    assert b"admin/data/alerts" in output


# ============================================================================
# Tests for Request Helper Functions
# ============================================================================


def test_get_limit_offset_defaults():
    """Test that get_limit_offset returns default values when params are missing."""
    request = DummyRequest()
    assert web.get_limit_offset(request) == (10, 0)


def test_get_limit_offset_values():
    """Test that get_limit_offset correctly parses limit and offset params."""
    request = DummyRequest(args={b"limit": [b"25"], b"offset": [b"5"]})
    assert web.get_limit_offset(request) == (25, 5)


def test_get_sort_n_order():
    """
    Test that get_sort_n_order correctly parses and validates sort parameters.
    
    - Valid sort/order values should be returned as-is
    - Invalid values should fall back to defaults
    """
    request = DummyRequest(args={b"sort": [b"counter"], b"order": [b"asc"]})
    sort, order = web.get_sort_n_order(request, default_sort="last_seen", allow_list=["counter", "last_seen"])
    assert sort == "counter"
    assert order == "asc"

    request = DummyRequest(args={b"sort": [b"bad"], b"order": [b"bad"]})
    sort, order = web.get_sort_n_order(request, default_sort="last_seen", allow_list=["counter", "last_seen"])
    assert sort == "last_seen"
    assert order == "DESC"


def test_get_host_url():
    """
    Test URL extraction for base host URLs.
    
    - Standard requests: Extract scheme + domain from URL
    - Ingress requests: Use X-Ingress-Path header (for Home Assistant)
    """
    request = DummyRequest(url="http://example.com/admin")
    assert web.get_host_url(request, "admin") == "http://example.com/"

    ingress_request = DummyRequest(ingress="/ingress")
    assert web.get_host_url(ingress_request, "admin") == "/ingress/"


def test_get_host_url_no_match():
    """Test that get_host_url returns empty string when the page name doesn't match the URL."""
    request = DummyRequest(url="http://example.com/dns")
    assert web.get_host_url(request, "admin") == ""


# ============================================================================
# Tests for Database Operations
# ============================================================================


def test_sql_action_roundtrip(tmp_path, monkeypatch):
    """
    Test basic database operations: create table, insert data, and select data.
    
    Verifies that sql_action can perform DDL and DML operations and return results.
    """
    monkeypatch.setattr(web, "CONFIG_DB_PATH", str(tmp_path))
    monkeypatch.setattr(web, "CONFIG_DB_NAME", "test.db")

    assert web.sql_action("CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT)", ()) is not False
    assert web.sql_action("INSERT INTO sample (name) VALUES (?)", ("alpha",)) is not False
    rows = web.sql_action("SELECT name FROM sample", ())
    assert rows == [("alpha",)]


def test_sql_action_requires_params():
    """Test that sql_action rejects queries without a params tuple (security measure)."""
    assert web.sql_action("SELECT 1", None) is False


def test_bootstrap_creates_schema(tmp_path, monkeypatch):
    """
    Test that bootstrap() successfully creates the database schema.
    
    Also verifies that bootstrap is idempotent (can be run multiple times).
    """
    monkeypatch.setattr(web, "CONFIG_DB_PATH", str(tmp_path))
    monkeypatch.setattr(web, "CONFIG_DB_NAME", "test.db")
    monkeypatch.setattr(
        web,
        "DB_SCHEMA",
        [("simple", 'CREATE TABLE "simple" ("id" INTEGER)')],
    )

    assert web.bootstrap() is True
    assert web.bootstrap() is True


# ============================================================================
# Tests for Data API Endpoints
# ============================================================================


def test_data_alerts_page_get(tmp_path, monkeypatch):
    """
    Test the alerts data API endpoint.
    
    Verifies that:
    - Alerts are returned in JSON format
    - Search filtering works correctly
    - Result count matches filtered data
    """
    setup_data_db(tmp_path, monkeypatch)
    web.sql_action(
        f'INSERT INTO "{web.DB_T_ALERTS}" ("id", "timestamp", "type", "src_ip", "message", "unread") VALUES (?, ?, ?, ?, ?, ?)',
        ("a1", "2026-02-09T00:00:00+00:00", "dns-domain", "1.2.3.4", "Alert A", 1),
    )
    web.sql_action(
        f'INSERT INTO "{web.DB_T_ALERTS}" ("id", "timestamp", "type", "src_ip", "message", "unread") VALUES (?, ?, ?, ?, ?, ?)',
        ("a2", "2026-02-09T01:00:00+00:00", "dns-query", "5.6.7.8", "Alert B", 1),
    )

    request = DummyRequest(
        args={
            b"limit": [b"10"],
            b"offset": [b"0"],
            b"search": [b"Alert A"],
        }
    )
    output = web.DataAlertsPage().render_GET(request)
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 1
    assert data["rows"][0]["id"] == "a1"


def test_data_dns_domains_page_get_and_post(tmp_path, monkeypatch):
    """
    Test the DNS domains data API endpoint (GET and POST).
    
    GET test: Verifies domains are returned with correct data
    POST test: Verifies inline editing updates domain actions (e.g., pass -> block)
    """
    setup_data_db(tmp_path, monkeypatch)
    web.sql_action(
        f'INSERT INTO "{web.DB_T_NETWORKS}" ("id", "ip", "type", "action", "created", "name") VALUES (?, ?, ?, ?, ?, ?)',
        ("n1", "192.168.1.0/24", "network", "learn", "2026-02-09T00:00:00+00:00", "lan"),
    )
    web.sql_action(
        f'INSERT INTO "{web.DB_T_DOMAINS}" ("id", "domain", "counter", "scope", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?)',
        ("d1", "example.com", 1, "n1", "pass", "2026-02-09T00:00:00+00:00"),
    )

    output = web.DataDNSDomainsPage().render_GET(DummyRequest(args={b"limit": [b"10"], b"offset": [b"0"]}))
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 1
    assert data["rows"][0]["domain"] == "example.com"
    assert data["rows"][0]["alert"] == 1

    post_request = DummyRequest(args={b"name": [b"alert"], b"value": [b"0"], b"pk": [b"d1"]})
    assert web.DataDNSDomainsPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "alert" FROM "{web.DB_T_DOMAINS}" WHERE id = ?', ("d1",))
    assert rows[0][0] == 0

    post_request = DummyRequest(args={b"name": [b"action"], b"value": [b"block"], b"pk": [b"d1"]})
    assert web.DataDNSDomainsPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "action" FROM "{web.DB_T_DOMAINS}" WHERE id = ?', ("d1",))
    assert rows[0][0] == "block"


def test_data_dns_queries_page_get_and_post(tmp_path, monkeypatch):
    """
    Test the DNS queries data API endpoint (GET and POST).
    
    GET test: Verifies individual DNS queries are returned
    POST test: Verifies inline editing updates query actions
    """
    setup_data_db(tmp_path, monkeypatch)
    web.sql_action(
        f'INSERT INTO "{web.DB_T_NETWORKS}" ("id", "ip", "type", "action", "created", "name") VALUES (?, ?, ?, ?, ?, ?)',
        ("n1", "192.168.1.0/24", "network", "learn", "2026-02-09T00:00:00+00:00", "lan"),
    )
    web.sql_action(
        f'INSERT INTO "{web.DB_T_DOMAINS}" ("id", "domain", "counter", "scope", "action", "last_seen") VALUES (?, ?, ?, ?, ?, ?)',
        ("d1", "example.com", 1, "n1", "pass", "2026-02-09T00:00:00+00:00"),
    )
    web.sql_action(
        f'INSERT INTO "{web.DB_T_QUERIES}" ("id", "src", "scope_id", "query", "query_type", "counter", "action", "last_seen", "domain_id") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ("q1", "1.2.3.4", "n1", "example.com", "A", 1, "pass", "2026-02-09T00:00:00+00:00", "d1"),
    )

    output = web.DataDNSQueriesPage().render_GET(DummyRequest(args={b"limit": [b"10"], b"offset": [b"0"]}))
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 1
    assert data["rows"][0]["query"] == "example.com"

    post_request = DummyRequest(args={b"name": [b"action"], b"value": [b"block"], b"pk": [b"q1"]})
    assert web.DataDNSQueriesPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "action" FROM "{web.DB_T_QUERIES}" WHERE id = ?', ("q1",))
    assert rows[0][0] == "block"


def test_data_tuning_hosts_page_get_and_post(tmp_path, monkeypatch):
    """
    Test the hosts tuning data API endpoint (GET and POST).
    
    GET test: Verifies known hosts are listed
    POST test: Verifies host names can be updated via inline editing
    """
    setup_data_db(tmp_path, monkeypatch)
    web.sql_action(
        f'INSERT INTO "{web.DB_T_HOSTS}" ("id", "ip", "scope_id", "name") VALUES (?, ?, ?, ?)',
        ("h1", "10.0.0.10", "n1", "device"),
    )

    output = web.DataTuningHostPage().render_GET(DummyRequest(args={b"limit": [b"10"], b"offset": [b"0"]}))
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 1
    assert data["rows"][0]["ip"] == "10.0.0.10"

    post_request = DummyRequest(args={b"name": [b"name"], b"value": [b"router"], b"pk": [b"h1"]})
    assert web.DataTuningHostPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "name" FROM "{web.DB_T_HOSTS}" WHERE id = ?', ("h1",))
    assert rows[0][0] == "router"


def test_data_tuning_networks_page_get_and_post(tmp_path, monkeypatch):
    """
    Test the network tuning data API endpoint (GET and POST).
    
    GET test: Verifies network scopes are listed
    POST test: Verifies network actions can be updated (e.g., learn -> block)
    """
    setup_data_db(tmp_path, monkeypatch)
    web.sql_action(
        f'INSERT INTO "{web.DB_T_NETWORKS}" ("id", "ip", "type", "action", "created", "name") VALUES (?, ?, ?, ?, ?, ?)',
        ("n1", "192.168.1.0/24", "network", "learn", "2026-02-09T00:00:00+00:00", "lan"),
    )

    output = web.DataTuningNetworkPage().render_GET(DummyRequest(args={b"limit": [b"10"], b"offset": [b"0"]}))
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 1
    assert data["rows"][0]["ip"] == "192.168.1.0/24"

    post_request = DummyRequest(args={b"name": [b"action"], b"value": [b"block"], b"pk": [b"n1"]})
    assert web.DataTuningNetworkPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "action" FROM "{web.DB_T_NETWORKS}" WHERE id = ?', ("n1",))
    assert rows[0][0] == "block"


def test_data_tuning_dns_ignored_page_get_and_post(tmp_path, monkeypatch):
    """
    Test the DNS ignored tuning data API endpoint (GET and POST).
    
    GET test: Verifies ignored domains and queries are listed
    POST test: Verifies alert status can be toggled (e.g., 0 -> 1)
    """
    setup_data_db(tmp_path, monkeypatch)
    # Add an ignored domain
    web.sql_action(
        f'INSERT INTO "{web.DB_T_DOMAINS}" ("id", "domain", "counter", "scope", "action", "last_seen", "alert") VALUES (?, ?, ?, ?, ?, ?, ?)',
        ("d_ignored", "ignored.com", 5, "n1", "pass", "2026-02-09T00:00:00+00:00", 0),
    )
    # Add an ignored query
    web.sql_action(
        f'INSERT INTO "{web.DB_T_QUERIES}" ("id", "src", "scope_id", "query", "query_type", "counter", "action", "last_seen", "domain_id", "alert") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ("q_ignored", "1.2.3.4", "n1", "secret.com", "A", 10, "pass", "2026-02-09T00:00:00+00:00", "d1", 0),
    )

    # Test GET
    output = web.DataTuningDNSIgnoredPage().render_GET(DummyRequest(args={b"limit": [b"10"], b"offset": [b"0"]}))
    data = json.loads(output.decode("utf-8"))
    assert data["total"] == 2
    # Records could be in any order depending on default sort, but let's check names
    names = [row["name"] for row in data["rows"]]
    assert "ignored.com" in names
    assert "secret.com" in names

    # Test POST (re-enable alert for domain)
    post_request = DummyRequest(args={b"name": [b"alert"], b"value": [b"1"], b"pk": [b"d_ignored"]})
    assert web.DataTuningDNSIgnoredPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "alert" FROM "{web.DB_T_DOMAINS}" WHERE id = ?', ("d_ignored",))
    assert rows[0][0] == 1

    # Test POST (re-enable alert for query)
    post_request = DummyRequest(args={b"name": [b"alert"], b"value": [b"1"], b"pk": [b"q_ignored"]})
    assert web.DataTuningDNSIgnoredPage().render_POST(post_request) == b"Ok"
    rows = web.sql_action(f'SELECT "alert" FROM "{web.DB_T_QUERIES}" WHERE id = ?', ("q_ignored",))
    assert rows[0][0] == 1


def test_data_roots():
    """
    Test that the data API root resources route to the correct child pages.
    
    Tests the resource tree structure:
    - /data/alerts -> DataAlertsPage
    - /data/dns/domains -> DataDNSDomainsPage
    - /data/dns/queries -> DataDNSQueriesPage
    - /data/tuning/networks -> DataTuningNetworkPage
    - /data/tuning/hosts -> DataTuningHostPage
    """
    dns_root = web.DataDNSRoot()
    assert isinstance(dns_root.getChild(b"domains", DummyRequest()), web.DataDNSDomainsPage)
    assert isinstance(dns_root.getChild(b"queries", DummyRequest()), web.DataDNSQueriesPage)
    assert dns_root.render_GET(DummyRequest()) == b'{"data":"dns"}'

    tuning_root = web.DataTuningRoot()
    assert isinstance(tuning_root.getChild(b"networks", DummyRequest()), web.DataTuningNetworkPage)
    assert isinstance(tuning_root.getChild(b"hosts", DummyRequest()), web.DataTuningHostPage)
    assert isinstance(tuning_root.getChild(b"dnsignored", DummyRequest()), web.DataTuningDNSIgnoredPage)
    assert tuning_root.render_GET(DummyRequest()) == b'{"data":"tuning"}'

    data_root = web.DataRoot()
    assert isinstance(data_root.getChild(b"alerts", DummyRequest()), web.DataAlertsPage)
    assert isinstance(data_root.getChild(b"dns", DummyRequest()), web.DataDNSRoot)
    assert isinstance(data_root.getChild(b"tuning", DummyRequest()), web.DataTuningRoot)
    assert data_root.render_GET(DummyRequest()) == b'{"data":"root"}'


# ============================================================================
# Tests for Webhook Alert Handling
# ============================================================================


def test_webhook_render_get():
    """Test that GET requests to /notify return a humorous message."""
    output = web.Webhook().render_GET(DummyRequest())
    assert b"Kill All Humans!" in output


def test_webhook_blocks_non_localhost(monkeypatch):
    """Test that webhook rejects POST requests from non-localhost sources for security."""
    monkeypatch.setattr(web, "DEBUG_MODE", False)
    output = web.Webhook().render_POST(DummyRequest(content=b"{}", peer_host="10.0.0.1"))
    assert output == b"No \n"


def test_webhook_invalid_json_returns_decode_failed(tmp_path, monkeypatch):
    """Test that webhook handles malformed JSON gracefully."""
    setup_data_db(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "DEBUG_MODE", False)
    output = web.Webhook().render_POST(DummyRequest(content=b"not-json"))
    assert output == b"Decode Failed "


def test_webhook_dns_logdata_does_not_insert(tmp_path, monkeypatch):
    """Test that DNS log messages (non-alerts) are not inserted into the alerts table."""
    setup_data_db(tmp_path, monkeypatch)
    data = {"type": "dns", "logdata": {"msg": "DNS started"}}
    output = web.Webhook().render_POST(DummyRequest(content=json.dumps(data).encode("utf-8")))
    assert output == b"ok \n"
    rows = web.sql_action(f'SELECT id FROM "{web.DB_T_ALERTS}"', ())
    assert rows == []


def test_webhook_dns_domain_and_query_insert(tmp_path, monkeypatch):
    """
    Test that DNS anomaly alerts are properly inserted into the database.
    
    Tests both alert types:
    - dns-domain: New domain detected
    - dns-query: Anomalous query detected
    """
    setup_data_db(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "HA_NOTIFY", False, raising=False)
    monkeypatch.setattr(web, "HA_WEBHOOK", None, raising=False)

    data = {
        "type": "dns",
        "alert_type": "dns-domain",
        "timestamp": "2026-02-09T00:00:00+00:00",
        "src_ip": "1.2.3.4",
        "domain": "example.com",
        "query": "example.com",
    }
    output = web.Webhook().render_POST(DummyRequest(content=json.dumps(data).encode("utf-8")))
    assert output == b"ok \n"

    data = {
        "type": "dns",
        "alert_type": "dns-query",
        "timestamp": "2026-02-09T00:00:01+00:00",
        "src_ip": "1.2.3.4",
        "domain": "example.com",
        "query": "example.com",
    }
    output = web.Webhook().render_POST(DummyRequest(content=json.dumps(data).encode("utf-8")))
    assert output == b"ok \n"

    rows = web.sql_action(f'SELECT type, message FROM "{web.DB_T_ALERTS}" ORDER BY timestamp', ())
    assert rows[0][0] == "dns-domain"
    assert "Domain anomaly example.com from 1.2.3.4" in rows[0][1]
    assert rows[1][0] == "dns-query"
    assert "Query anomaly example.com from 1.2.3.4" in rows[1][1]


def test_webhook_canary_inserts(tmp_path, monkeypatch):
    """
    Test that OpenCanary honeypot alerts are properly processed and inserted.
    
    Verifies:
    - Alert is inserted with correct type (canary-p{port})
    - Message includes source IP and honeypot credentials
    """
    setup_data_db(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "HA_NOTIFY", False, raising=False)
    monkeypatch.setattr(web, "HA_WEBHOOK", None, raising=False)

    canary = {
        "utc_time": "2026-02-09T01:02:03",
        "dst_port": 22,
        "src_host": "5.6.7.8",
        "honeycred": True,
        "logdata": {"USERAGENT": "curl/1.0", "USERNAME": "root", "PASSWORD": "toor"},
    }
    data = {"type": "opencanary", "message": json.dumps(canary)}
    output = web.Webhook().render_POST(DummyRequest(content=json.dumps(data).encode("utf-8")))
    assert output == b"ok \n"

    rows = web.sql_action(f'SELECT type, message FROM "{web.DB_T_ALERTS}"', ())
    assert rows[0][0] == "canary-p22"
    assert "HoneyPot Login from 5.6.7.8" in rows[0][1]
    assert "Honey Credentials root & toor" in rows[0][1]


# ============================================================================
# Tests for Home Assistant Integration
# ============================================================================


def test_post_to_ha_hook_success(monkeypatch):
    """
    Test successful webhook posting to Home Assistant.
    
    Verifies:
    - Correct URL is constructed with webhook ID
    - Authorization header includes supervisor token
    - Returns True on successful POST
    """
    calls = {}

    def fake_post(json, url, headers, timeout):
        calls["json"] = json
        calls["url"] = url
        calls["headers"] = headers
        calls["timeout"] = timeout
        return DummyResponse(status_code=200)

    monkeypatch.setenv("SUPERVISOR_TOKEN", "token")
    monkeypatch.setattr(web, "requests", SimpleNamespace(post=fake_post), raising=False)

    assert web.post_to_ha_hook({"msg": "hi"}, webhook_id="abc") is True
    assert calls["url"].endswith("/abc")
    assert calls["headers"]["Authorization"] == "Bearer token"


def test_post_to_ha_hook_failure(monkeypatch):
    """Test that post_to_ha_hook handles HTTP errors gracefully and returns False."""
    def fake_post(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(web, "requests", SimpleNamespace(post=fake_post), raising=False)

    assert web.post_to_ha_hook({"msg": "hi"}, webhook_id="abc") is False


def test_post_to_ha_notify(monkeypatch):
    """
    Test posting persistent notifications to Home Assistant.
    
    Verifies:
    - Notification title includes alert type
    - Notification message is passed through correctly
    - Returns True on success
    """
    calls = {}

    def fake_post(json, url, headers, timeout):
        calls["json"] = json
        calls["url"] = url
        calls["headers"] = headers
        calls["timeout"] = timeout
        return DummyResponse(status_code=200)

    monkeypatch.setenv("SUPERVISOR_TOKEN", "token")
    monkeypatch.setattr(web, "requests", SimpleNamespace(post=fake_post), raising=False)

    assert web.post_to_ha_notify({"type": "opencanary", "message": "hello"}) is True
    assert "Home Detector Alert | opencanary" in calls["json"]["title"]
    assert calls["json"]["message"] == "hello"
