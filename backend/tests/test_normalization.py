import pytest

from app.services.normalization import normalize_line


# ---------- SSH ----------

def test_ssh_failed_login_syslog_format():
    line = "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 52344 ssh2"
    event = normalize_line(line)

    assert event["event_type"] == "authentication_failure"
    assert event["category"] == "authentication"
    assert event["source_type"] == "ssh"
    assert event["source_ip"] == "192.168.1.50"
    assert event["source_port"] == 52344
    assert event["destination_port"] == 22
    assert event["username"] == "root"
    assert event["hostname"] == "server"
    assert event["action"] == "login"
    assert event["outcome"] == "failure"
    assert event["raw_message"] == line


def test_ssh_failed_login_invalid_user():
    line = "Aug 28 10:31:15 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = normalize_line(line)
    assert event["username"] == "admin"
    assert event["outcome"] == "failure"


def test_ssh_successful_login():
    line = "Aug 28 10:31:15 server sshd[1234]: Accepted password for alice from 10.0.0.5 port 4444 ssh2"
    event = normalize_line(line)
    assert event["event_type"] == "authentication_success"
    assert event["outcome"] == "success"
    assert event["username"] == "alice"


def test_ssh_iso_timestamp_format():
    line = "2026-08-20T03:14:11 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = normalize_line(line)
    assert event["event_type"] == "authentication_failure"
    assert event["timestamp"].year == 2026


def test_ssh_ipv6_source():
    line = "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 2001:db8::1 port 52344 ssh2"
    event = normalize_line(line)
    assert event["source_ip"] == "2001:db8::1"


def test_ssh_malformed_line_raises():
    # Looks like an SSH auth line but is missing the "from <ip> port <port>" part.
    line = "Aug 28 10:31:15 server sshd[1234]: Failed password for root"
    with pytest.raises(ValueError):
        normalize_line(line)


def test_ssh_missing_username_falls_through_to_unparsed():
    line = "Aug 28 10:31:15 server sshd[1234]: something unrelated happened"
    event = normalize_line(line)
    # Doesn't match SSH's auth-attempt shape at all -> falls back to generic, not an SSH error.
    assert event["event_type"] == "unparsed"


# ---------- Nginx ----------

def test_nginx_normal_request():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /index HTTP/1.1" 200 512'
    event = normalize_line(line)

    assert event["event_type"] == "http_request"
    assert event["category"] == "web"
    assert event["source_type"] == "nginx"
    assert event["source_ip"] == "203.0.113.5"
    assert event["outcome"] == "success"
    assert event["severity"] == "info"
    assert event["parsed_fields"]["method"] == "GET"
    assert event["parsed_fields"]["path"] == "/index"
    assert event["parsed_fields"]["status_code"] == 200
    assert event["parsed_fields"]["response_bytes"] == 512


def test_nginx_4xx_request():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /admin HTTP/1.1" 404 512'
    event = normalize_line(line)
    assert event["event_type"] == "http_error"
    assert event["outcome"] == "failure"
    assert event["severity"] == "low"


def test_nginx_5xx_request():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "POST /api HTTP/1.1" 500 0'
    event = normalize_line(line)
    assert event["event_type"] == "http_error"
    assert event["severity"] == "high"


def test_nginx_with_referer_and_user_agent():
    line = ('203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /login HTTP/1.1" 404 1234 '
            '"-" "Mozilla/5.0"')
    event = normalize_line(line)
    assert event["parsed_fields"]["user_agent"] == "Mozilla/5.0"


def test_nginx_malformed_line_raises():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /admin HTTP/1.1" NOTASTATUS 512'
    with pytest.raises(ValueError):
        normalize_line(line)


# ---------- generic ----------

def test_blank_line_returns_none():
    assert normalize_line("   ") is None


def test_unrecognised_line_falls_back_to_generic():
    event = normalize_line("systemd[1]: Starting Daily apt upgrade...")
    assert event["event_type"] == "unparsed"
    assert event["category"] == "application"
    assert event["outcome"] == "unknown"
