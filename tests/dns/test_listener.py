# Test for dns/listener.py
# Created by Gemini using model gemini-1.5-pro-001 on 2026-02-05
# Modified by Gemini using model gemini-1.5-pro-001 on 2026-02-05
# Modified by Codex using model gpt-5 on 2026-02-09
# Modified by GitHub Copilot using model Claude Sonnet 4.5 on 2026-02-11
# Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
"""
Unit tests for the dns/listener.py module.

This test suite covers:
- DNS interceptor initialization and configuration
- ID generation for unique resource identification (hashing)
- Packet filtering and action decisions (pass/block)
- Network scope handling (host, network CIDR, IP ranges)
- Learning mode with automatic transition to blocking after duration expires
- DNS query tracking in SQLite database
- Domain tracking and counter updates
- Resolver configuration from various sources (resolv.conf, environment variables)
- Domain resolution and SOA (Start of Authority) requests

The DNS listener is a custom DNS server that learns normal traffic patterns
and can detect/block anomalous DNS queries from IoT devices.
"""

from __future__ import annotations

from io import StringIO
import datetime

import pytest

import dns.listener as listener


# ============================================================================
# Test Fixtures
# ============================================================================
# These fixtures set up the test environment with a temporary database and
# a configured DNSInterceptor instance. They ensure clean state for each test
# and proper cleanup of database connections.


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    """
    Create a temporary test database with the required schema.
    
    This fixture:
    - Configures the listener module to use a temporary database path
    - Calls bootstrap() to create all necessary tables
    - Returns the path to the database file for tests that need direct access
    
    Args:
        tmp_path: Pytest fixture providing a temporary directory
        monkeypatch: Pytest fixture for modifying module attributes
    
    Returns:
        Path object pointing to the test database file
    """
    monkeypatch.setattr(listener, "CONFIG_DB_PATH", str(tmp_path))
    monkeypatch.setattr(listener, "CONFIG_DB_NAME", "test.db")
    assert listener.bootstrap(listener.logger)
    return tmp_path / "test.db"


@pytest.fixture
def interceptor(db_path):
    """
    Create a DNSInterceptor instance for testing.
    
    This fixture:
    - Creates a DNSInterceptor with test configuration (upstream DNS: 8.8.8.8)
    - Configures local network scope (127.0.0.1 as a monitored host)
    - Ensures the database connection is properly closed after tests
    
    The DNSInterceptor is the core component that:
    - Intercepts DNS queries from monitored networks
    - Learns normal traffic patterns during learning mode
    - Blocks or allows queries based on configured rules
    - Tracks queries and domains in the database
    
    Args:
        db_path: Path to the test database (from db_path fixture)
    
    Yields:
        DNSInterceptor instance ready for testing
    """
    instance = listener.DNSInterceptor(
        upstream=["8.8.8.8"],
        dnsi_logger=listener.logger,
        local_ips=[{"address": "127.0.0.1", "type": "host"}],
    )
    try:
        yield instance
    finally:
        instance.sql_connection.close()


# ============================================================================
# Tests for ID Generation and Packet Filtering
# ============================================================================


def test_create_id_and_pass_packet(interceptor):
    """
    Test ID generation and packet filtering logic.
    
    createID():
    - Creates a SHA-256 hash from a list of strings to uniquely identify
      DNS queries, domains, and network scopes
    - Returns an error message if input is not a list
    
    passThePacket():
    - Determines whether a DNS query should be allowed through based on action
    - Returns False for "block" action (query is dropped)
    - Returns True for "pass" action (query is forwarded to upstream DNS)
    """
    expected = "91fd4603f81dbd9d772bb73cc8bb682dc287be3d492ca5e275a7dfd7111de212"
    assert interceptor.createID(["alpha", "beta"]) == expected
    assert interceptor.createID("alpha") == "ERROR: Input not list"
    assert interceptor.passThePacket("block") is False
    assert interceptor.passThePacket("pass") is True


# ============================================================================
# Tests for Network Scope Handling
# ============================================================================


def test_getscope_variants(interceptor):
    """
    Test network scope generation for different address types.
    
    The DNS listener can monitor three types of network scopes:
    1. Host: Single IP address (e.g., 192.168.1.10)
    2. Network: CIDR notation (e.g., 192.168.2.0/24)
    3. Range: IP range (e.g., 192.168.3.10-192.168.3.20)
    
    Each scope type uses netaddr library to generate an IPSet that can
    efficiently check if a source IP belongs to the monitored scope.
    """
    host_scope = interceptor.getscope("host", "192.168.1.10")
    assert "192.168.1.10" in host_scope

    net_scope = interceptor.getscope("network", "192.168.2.0/24")
    assert "192.168.2.42" in net_scope

    range_scope = interceptor.getscope("range", "192.168.3.10-192.168.3.20")
    assert "192.168.3.10" in range_scope
    assert "192.168.3.20" in range_scope


# ============================================================================
# Tests for Learning Mode
# ============================================================================


def test_learning_mode_revalidation_updates_action(interceptor, monkeypatch):
    """
    Test that learning mode automatically transitions to blocking after expiration.
    
    Learning mode allows the DNS listener to observe normal DNS traffic patterns
    for a configurable duration (LEARNING_DURATION). After this period expires,
    the network scope transitions from "learn" to "block" mode.
    
    In blocking mode:
    - Previously seen domains continue to pass
    - New/unknown domains trigger alerts and are blocked
    
    This test:
    1. Sets LEARNING_DURATION to 0 (immediate expiration)
    2. Creates a network scope with creation time 1 day in the past
    3. Calls learningModeReValidation() to check if learning period expired
    4. Verifies the action changed from "learn" to "block"
    5. Verifies TTL (time-to-live) for the decision is returned
    """
    monkeypatch.setattr(listener, "LEARNING_DURATION", 0)
    scope_id = interceptor.createID(["host", "10.10.10.10"])
    created = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)).isoformat(timespec="seconds")
    with interceptor.lock:
        cursor = interceptor.sql_connection.cursor()
        cursor.execute(
            f'INSERT INTO "{listener.DB_T_NETWORKS}" ("id", "ip", "type", "action", "created") VALUES (?, ?, ?, ?, ?)',
            (scope_id, "10.10.10.10", "host", "learn", created),
        )
        interceptor.sql_connection.commit()
        cursor.close()

    action, ttl = interceptor.learningModeReValidation(scope_id, "learn", created)
    assert action == "block"
    assert ttl is not None


# ============================================================================
# Tests for DNS Query Tracking
# ============================================================================


def test_find_sql_query_id_and_sql_dns_query(interceptor):
    """
    Test DNS query tracking in the database.
    
    The interceptor tracks individual DNS queries in the database:
    - Each unique combination of (source IP, domain, query type) gets a unique ID
    - First occurrence: Returns None for sql_id, initializes counter to 1
    - Subsequent occurrences: Returns existing sql_id, increments counter
    
    This test verifies the complete query tracking workflow:
    1. Check for non-existent query (returns None, counter=1, action="pass")
    2. Insert new query into database via sqlDNSquery()
    3. Verify query now exists with correct ID and action
    4. Update existing query (simulate second occurrence)
    5. Verify counter incremented to 2
    
    The counter helps identify frequently-queried domains, which can be useful
    for tuning detection rules.
    """
    query_id = interceptor.createID(["1.2.3.4", "example.com", "A"])
    sql_id, counter, action, domain_id, alert = interceptor.findSQLQueryID(query_id, learning_mode=True)
    assert sql_id is None
    assert counter == 1
    assert action == "pass"
    assert domain_id is None
    assert alert == 0

    sql_id, action = interceptor.sqlDNSquery(
        {
            "result": None,
            "id": query_id,
            "counter": 1,
            "action": "pass",
            "scope_id": "scope",
            "src": "1.2.3.4",
            "query": "example.com",
            "query_type": "A",
            "last_seen": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "domain_id": None,
            "alert": 0,
        }
    )
    assert sql_id == query_id
    assert action == "pass"

    sql_id, counter, action, domain_id, alert = interceptor.findSQLQueryID(query_id, learning_mode=True)
    assert sql_id == query_id
    assert counter == 1
    assert action == "pass"
    assert domain_id == "None"
    assert alert == 0

    interceptor.sqlDNSquery(
        {
            "result": sql_id,
            "id": query_id,
            "counter": counter,
            "action": action,
            "scope_id": "scope",
            "src": "1.2.3.4",
            "query": "example.com",
            "query_type": "A",
            "last_seen": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "domain_id": None,
        }
    )
    sql_id, counter, action, domain_id, alert = interceptor.findSQLQueryID(query_id, learning_mode=True)
    assert counter == 2
    assert alert == 0


# ============================================================================
# Tests for Domain Tracking
# ============================================================================


def test_sql_domains_insert_and_update(interceptor):
    """
    Test domain tracking with counter updates.
    
    The interceptor tracks domains separately from individual queries:
    - Domains are scoped to network ranges (same domain in different scopes
      is tracked separately)
    - First occurrence: Insert new domain with counter=1
    - Subsequent occurrences: Update last_seen timestamp and increment counter
    
    This test verifies:
    1. New domain is inserted and returns a domain_id
    2. Second occurrence of same domain returns the same domain_id
    3. Counter is incremented to 2 after the second call
    
    Domain counters help identify:
    - Frequently accessed domains (likely legitimate)
    - Rarely accessed domains (potentially suspicious)
    """
    scope_id = interceptor.createID(["host", "127.0.0.1"])
    action, domain_id, alert = interceptor.sqlDomains("example.com", scope_id, "pass", learning_mode=True)
    assert action == "pass"
    assert domain_id is not None
    assert alert == 0

    action, domain_id_again, alert_again = interceptor.sqlDomains("example.com", scope_id, "pass", learning_mode=True)
    assert domain_id_again == domain_id
    assert alert_again == 0
    sql_cursor = interceptor.sql_connection.cursor()
    rows = sql_cursor.execute(
        f'SELECT "counter" FROM "{listener.DB_T_DOMAINS}" WHERE id = ?', (domain_id,)
    ).fetchall()
    sql_cursor.close()
    assert rows[0][0] == 2


# ============================================================================
# Tests for Resolver Configuration
# ============================================================================


def test_read_resolve_conf_parses_nameservers(monkeypatch):
    """
    Test parsing of /etc/resolv.conf for upstream DNS servers.
    
    The DNS listener needs to know which upstream DNS servers to forward
    queries to after performing its security checks.
    
    This test verifies that readResolveConf():
    - Parses nameserver lines from resolv.conf
    - Ignores comments and empty lines
    - Handles leading whitespace
    - Returns a list of resolver IP addresses
    """
    def fake_open(*_args, **_kwargs):
        return StringIO("nameserver 1.1.1.1\n# comment\n nameserver 8.8.8.8\n")

    monkeypatch.setattr("builtins.open", fake_open)
    resolvers = listener.readResolveConf([], listener.logger)
    assert resolvers == ["1.1.1.1", "8.8.8.8"]


def test_get_resolvers_from_upstream(monkeypatch):
    """
    Test resolver configuration from UPSTREAM_RESOLVERS and environment variables.
    
    The DNS listener can be configured to use specific upstream DNS servers
    rather than using the system's resolv.conf. This is useful in containerized
    environments like Home Assistant.
    
    This test verifies:
    1. Resolvers are read from UPSTREAM_RESOLVERS configuration
    2. Server names (like "home-assistant") are resolved via environment variables
    3. Port numbers are parsed correctly (or default to 53)
    4. Invalid ports fall back to default port 53
    5. Final format is "ip:port"
    """
    monkeypatch.setattr(
        listener,
        "UPSTREAM_RESOLVERS",
        [
            {"server": "9.9.9.9", "port": "54"},
            {"server": "home-assistant", "port": "invalid"},
        ],
    )
    monkeypatch.setenv("homeassistant", "10.0.0.1")
    resolvers = listener.getResolvers(listener.logger)
    assert resolvers == ["9.9.9.9:54", "10.0.0.1:53"]


# ============================================================================
# Tests for Domain Resolution
# ============================================================================


def test_find_domain_returns_none_on_no_response(interceptor, monkeypatch):
    """
    Test domain lookup failure handling.
    
    When a DNS query is received, the interceptor performs a SOA (Start of Authority)
    request to verify the domain exists and extract the authoritative domain name.
    
    If the SOA request fails (no response, timeout, NXDOMAIN):
    - Domain is returned as None
    - Action is set to SOA_FAIL_ACTION (typically "block" for security)
    - Domain ID is None (not tracked)
    
    This test:
    1. Mocks sendSOArequest to return None (simulating failure)
    2. Calls findDomain() to look up a domain
    3. Verifies failure is handled correctly with SOA_FAIL_ACTION
    
    This prevents malicious queries to non-existent or unreachable domains.
    """
    monkeypatch.setattr(interceptor, "sendSOArequest", lambda *_args, **_kwargs: None)
    scope_id = interceptor.local_networks[0]["id"]
    domain, action, domain_id, alert = interceptor.findDomain("example.com", scope_id, True)
    assert domain is None
    assert action == listener.SOA_FAIL_ACTION
    assert domain_id is None
    assert alert == 0


# ============================================================================
# New Tests for Coverage Improvement
# ============================================================================


def test_resolve_fake_a_records(interceptor, monkeypatch):
    """
    Test DNS resolve with fake A records mapping.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    from dnslib import DNSRecord
    monkeypatch.setitem(listener.FAKE_A_RECORDS, "testfake.com", "10.0.0.99")
    req = DNSRecord.question("testfake.com")
    class DummyHandler:
        client_address = ("127.0.0.1", 12345)
        protocol = "udp"
    
    reply = interceptor.resolve(req, DummyHandler())
    assert reply is not None
    answers = [str(r.rdata) for r in reply.rr]
    assert "10.0.0.99" in answers


def test_resolve_unknown_ip_block(interceptor, monkeypatch):
    """
    Test DNS resolve unknown IP blocking.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    from dnslib import DNSRecord, RCODE
    monkeypatch.setattr(listener, "UKNOWN_IP_PASS", False)
    req = DNSRecord.question("example.com")
    class DummyHandler:
        client_address = ("8.8.8.8", 12345)
        protocol = "udp"
    
    reply = interceptor.resolve(req, DummyHandler())
    assert reply.header.rcode == getattr(RCODE, "NXDOMAIN")


def test_resolve_unknown_ip_pass(interceptor, monkeypatch):
    """
    Test DNS resolve unknown IP passing through.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    from dnslib import DNSRecord
    monkeypatch.setattr(listener, "UKNOWN_IP_PASS", True)
    req = DNSRecord.question("example.com")
    class DummyHandler:
        client_address = ("8.8.8.8", 12345)
        protocol = "udp"
    
    monkeypatch.setattr(req, "send", lambda *args, **kwargs: req.pack())
    
    reply = interceptor.resolve(req, DummyHandler())
    assert reply is not None


def test_resolve_monitored_network_learning(interceptor, monkeypatch):
    """
    Test DNS resolve with monitored network in learning mode.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    from dnslib import DNSRecord, DNSQuestion, RR, SOA, QTYPE
    
    def fake_send_soa(soa_query, index=0, tcp=False):
        reply = soa_query.reply()
        reply.add_auth(RR("example.com", QTYPE.SOA, rdata=SOA("ns.example.com", "admin.example.com", (2026052601, 3600, 600, 86400, 3600))))
        return reply.pack()
    
    monkeypatch.setattr(interceptor, "sendSOArequest", fake_send_soa)
    
    req = DNSRecord.question("sub.example.com")
    class DummyHandler:
        client_address = ("127.0.0.1", 12345)
        protocol = "udp"
    
    monkeypatch.setattr(req, "send", lambda *args, **kwargs: req.pack())
    
    reply = interceptor.resolve(req, DummyHandler())
    assert reply is not None
    
    cursor = interceptor.sql_connection.cursor()
    rows = cursor.execute('SELECT domain, action FROM domains').fetchall()
    cursor.close()
    assert len(rows) > 0
    assert any(r[0] == "example.com." and r[1] == "pass" for r in rows)


def test_resolve_monitored_network_blocking(interceptor, monkeypatch):
    """
    Test DNS resolve with monitored network in blocking mode.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    from dnslib import DNSRecord, DNSQuestion, RR, SOA, QTYPE, RCODE
    
    monkeypatch.setattr(listener, "DNS_FIREWALL_ON", True)
    
    for net in interceptor.local_networks:
        net["action"] = "block"
        
    def fake_send_soa(soa_query, index=0, tcp=False):
        reply = soa_query.reply()
        reply.add_auth(RR("blockeddomain.com", QTYPE.SOA, rdata=SOA("ns.blockeddomain.com", "admin.blockeddomain.com", (2026052601, 3600, 600, 86400, 3600))))
        return reply.pack()
    
    monkeypatch.setattr(interceptor, "sendSOArequest", fake_send_soa)
    
    req = DNSRecord.question("test.blockeddomain.com")
    class DummyHandler:
        client_address = ("127.0.0.1", 12345)
        protocol = "udp"
        
    reply = interceptor.resolve(req, DummyHandler())
    assert reply is not None
    assert reply.header.rcode == getattr(RCODE, "NXDOMAIN")


def test_postwebhook_success(monkeypatch):
    """
    Test postwebhook success path.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    class MockResponse:
        status_code = 200
        content = b"ok"
    monkeypatch.setattr(listener.requests, "post", lambda *args, **kwargs: MockResponse())
    assert listener.postwebhook({"data": "test"}) is True


def test_postwebhook_non_200(monkeypatch):
    """
    Test postwebhook failure with non-200.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    class MockResponse:
        status_code = 500
        content = b"error"
    monkeypatch.setattr(listener.requests, "post", lambda *args, **kwargs: MockResponse())
    assert listener.postwebhook({"data": "test"}) is False


def test_postwebhook_exception(monkeypatch):
    """
    Test postwebhook failure with exception.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    def fake_post(*args, **kwargs):
        raise Exception("Connection error")
    monkeypatch.setattr(listener.requests, "post", fake_post)
    assert listener.postwebhook({"data": "test"}) is False


def test_bootstrap_migrations(tmp_path, monkeypatch):
    """
    Test bootstrap DB schema migrations.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    import sqlite3
    db_file = tmp_path / "test_migration.db"
    monkeypatch.setattr(listener, "CONFIG_DB_PATH", str(tmp_path))
    monkeypatch.setattr(listener, "CONFIG_DB_NAME", "test_migration.db")
    
    conn = sqlite3.connect(str(db_file))
    conn.execute('CREATE TABLE "domains" ("id" TEXT, "domain" TEXT, "counter" INTEGER, "scope" TEXT, "action" TEXT, "last_seen" TEXT)')
    conn.execute('INSERT INTO "domains" (id, domain, action) VALUES ("d1", "test.com", "pass")')
    conn.commit()
    conn.close()
    
    assert listener.bootstrap(listener.logger) is True
    
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(domains)")
    columns = [col[1] for col in cursor.fetchall()]
    assert "alert" in columns
    
    rows = cursor.execute("SELECT id, alert FROM domains").fetchall()
    cursor.close()
    conn.close()
    assert rows[0][1] == 0


def test_load_networks_invalid_ip(db_path, monkeypatch):
    """
    Test loading networks with invalid IP addresses.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    interceptor = listener.DNSInterceptor(
        upstream=["8.8.8.8"],
        dnsi_logger=listener.logger,
        local_ips=[
            {"address": "not-an-ip", "type": "host"},
            {"address": "127.0.0.1", "type": "host"}
        ]
    )
    assert len(interceptor.local_networks) == 1
    interceptor.sql_connection.close()


def test_load_networks_missing_type(db_path):
    """
    Test loading networks missing scope type parameter.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    interceptor = listener.DNSInterceptor(
        upstream=["8.8.8.8"],
        dnsi_logger=listener.logger,
        local_ips=[{"address": "127.0.0.2"}]
    )
    assert len(interceptor.local_networks) == 1
    assert "127.0.0.2" in interceptor.getscope("host", "127.0.0.2")
    interceptor.sql_connection.close()


def test_learning_mode_ttl_expired(interceptor, monkeypatch):
    """
    Test learningModeReValidation when TTL has expired.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    scope_id = interceptor.createID(["host", "127.0.0.1"])
    created = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2)
    ttl = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=listener.LOCAL_NETWORKS_TTL + 10)
    
    with interceptor.lock:
        cursor = interceptor.sql_connection.cursor()
        cursor.execute(
            f'UPDATE "{listener.DB_T_NETWORKS}" SET "action" = ? WHERE "id" = ?',
            ("block", scope_id)
        )
        interceptor.sql_connection.commit()
        cursor.close()
        
    action, new_ttl = interceptor.learningModeReValidation(scope_id, "learn", created, ttl=ttl)
    assert action == "block"
    assert new_ttl is not None


def test_get_resolvers_default(monkeypatch):
    """
    Test getResolvers fallback behavior when UPSTREAM_RESOLVERS is empty.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    monkeypatch.setattr(listener, "UPSTREAM_RESOLVERS", [])
    monkeypatch.setattr(listener, "readResolveConf", lambda r, log: [])
    resolvers = listener.getResolvers(listener.logger)
    assert resolvers == ["8.8.8.8", "1.1.1.1"]


def test_get_resolvers_env_missing(monkeypatch):
    """
    Test getResolvers fallback when host fails env resolution.
    Modified by Antigravity using model Gemini 3.5 Flash on 2026-05-26
    """
    monkeypatch.setattr(
        listener,
        "UPSTREAM_RESOLVERS",
        [
            {"server": "missing-host", "port": "53"},
        ],
    )
    resolvers = listener.getResolvers(listener.logger)
    assert resolvers == ["8.8.8.8", "1.1.1.1"]
