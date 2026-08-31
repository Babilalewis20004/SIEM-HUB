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


def test_ssh_missing_username_falls_through_to_syslog_fallback():
    line = "Aug 28 10:31:15 server sshd[1234]: something unrelated happened"
    event = normalize_line(line)
    # Doesn't match SSH's auth-attempt shape -> not an SSH error. The generic
    # syslog wrapper still recognises the envelope (tag "sshd"), so this is
    # no longer a bare "unparsed" event now that SyslogParser exists.
    assert event["source_type"] == "syslog"
    assert event["parsed_fields"]["tag"] == "sshd"


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


# ---------- Apache ----------

def test_apache_line_defaults_to_nginx_without_a_hint():
    # Apache's combined format is identical to Nginx's -- without an explicit
    # source hint there's no content-based way to tell them apart, so
    # auto-detection falls through to whichever is registered first.
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /index HTTP/1.1" 200 512'
    event = normalize_line(line)
    assert event["source_type"] == "nginx"


def test_apache_line_tagged_correctly_with_explicit_hint():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /index HTTP/1.1" 200 512'
    event = normalize_line(line, source_hint="apache")
    assert event["source_type"] == "apache"
    assert event["category"] == "web"
    assert event["parsed_fields"]["status_code"] == 200


def test_apache_5xx_with_hint_is_http_error():
    line = '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "POST /api HTTP/1.1" 500 0'
    event = normalize_line(line, source_hint="apache")
    assert event["event_type"] == "http_error"
    assert event["severity"] == "high"


def test_source_hint_ignored_when_line_does_not_match_hinted_parser():
    # source_hint="apache" on an SSH line shouldn't force a bad parse --
    # falls through to normal auto-detection.
    line = "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 52344 ssh2"
    event = normalize_line(line, source_hint="apache")
    assert event["source_type"] == "ssh"


# ---------- Firewall (iptables/UFW) ----------

def test_firewall_ufw_block():
    line = ("Aug 28 10:31:15 gateway kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= "
            "MAC=00:1a:2b:3c:4d:5e SRC=203.0.113.5 DST=10.0.0.5 LEN=60 TOS=0x00 "
            "PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 SYN URGP=0")
    event = normalize_line(line)

    assert event["source_type"] == "firewall"
    assert event["category"] == "network"
    assert event["event_type"] == "connection_blocked"
    assert event["outcome"] == "blocked"
    assert event["source_ip"] == "203.0.113.5"
    assert event["destination_ip"] == "10.0.0.5"
    assert event["destination_port"] == 22
    assert event["parsed_fields"]["protocol"] == "TCP"
    assert event["hostname"] == "gateway"


def test_firewall_ufw_allow():
    line = ("Aug 28 10:31:15 gateway kernel: [12345.678901] [UFW ALLOW] IN=eth0 OUT= "
            "SRC=10.0.0.9 DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=443")
    event = normalize_line(line)
    assert event["event_type"] == "connection_allowed"
    assert event["outcome"] == "success"


def test_firewall_plain_iptables_no_ufw_tag():
    line = "Aug 28 10:31:15 gateway kernel: [1.0] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.5 PROTO=UDP SPT=53 DPT=53"
    event = normalize_line(line)
    assert event["outcome"] == "unknown"
    assert event["event_type"] == "connection_logged"


def test_firewall_requires_src_dst_and_proto_all_present():
    # Has PROTO= but no SRC=/DST= -- matches() requires all three, so this
    # never gets claimed by FirewallParser. It's still a well-formed syslog
    # envelope, so the generic syslog fallback describes it instead of a bare
    # "unparsed" event.
    line = "Aug 28 10:31:15 gateway kernel: PROTO=TCP something else entirely"
    event = normalize_line(line)
    assert event["source_type"] == "syslog"


# ---------- Windows Security (4624/4625) ----------

def test_windows_failed_logon():
    line = ('{"EventID": 4625, "TimeCreated": "2026-08-20T03:14:11Z", "Computer": "WIN-DC01", '
            '"TargetUserName": "administrator", "IpAddress": "203.0.113.5", "LogonType": 3, '
            '"FailureReason": "Unknown user name or bad password"}')
    event = normalize_line(line)

    assert event["source_type"] == "windows_security"
    assert event["event_type"] == "authentication_failure"
    assert event["category"] == "authentication"
    assert event["outcome"] == "failure"
    assert event["username"] == "administrator"
    assert event["source_ip"] == "203.0.113.5"
    assert event["hostname"] == "WIN-DC01"
    assert event["timestamp"].tzinfo is None  # normalised to naive UTC
    assert event["parsed_fields"]["logon_type"] == 3


def test_windows_successful_logon():
    line = ('{"EventID": 4624, "TimeCreated": "2026-08-20T03:14:11Z", "Computer": "WIN-DC01", '
            '"TargetUserName": "alice", "IpAddress": "10.0.0.5", "LogonType": 3}')
    event = normalize_line(line)
    assert event["event_type"] == "authentication_success"
    assert event["outcome"] == "success"


def test_windows_local_logon_has_no_source_ip():
    line = ('{"EventID": 4624, "TimeCreated": "2026-08-20T03:14:11Z", "Computer": "WIN-DC01", '
            '"TargetUserName": "alice", "IpAddress": "-", "LogonType": 2}')
    event = normalize_line(line)
    assert event["source_ip"] is None


def test_windows_unhandled_event_id_falls_back_to_generic():
    line = '{"EventID": 4688, "TimeCreated": "2026-08-20T03:14:11Z", "Computer": "WIN-DC01"}'
    event = normalize_line(line)
    assert event["event_type"] == "unparsed"


def test_windows_malformed_json_with_supported_event_id_raises():
    line = '{"EventID": 4625, "TimeCreated": "2026-08-20T03:14:11Z"'  # truncated JSON
    with pytest.raises(ValueError):
        normalize_line(line)


# ---------- Generic syslog wrapper ----------

def test_syslog_with_pri_maps_severity():
    line = "<34>Aug 28 10:31:15 myhost su[1234]: 'su root' failed for lonvick on /dev/pts/8"
    event = normalize_line(line)

    assert event["source_type"] == "syslog"
    assert event["event_type"] == "syslog_message"
    assert event["category"] == "application"
    assert event["hostname"] == "myhost"
    assert event["parsed_fields"]["tag"] == "su"
    assert event["parsed_fields"]["pid"] == "1234"
    # <34> = facility 4, severity 2 ("crit") -> this app's "critical"
    assert event["severity"] == "critical"


def test_syslog_without_pri_defaults_to_info_severity():
    line = "Aug 28 10:31:15 myhost cron[999]: (root) CMD (/usr/bin/somejob)"
    event = normalize_line(line)
    assert event["severity"] == "info"
    assert event["parsed_fields"]["tag"] == "cron"


def test_syslog_rfc5424_iso_timestamp():
    line = "<165>1 2026-08-20T03:14:11.003Z myhost evntslog - ID47 - some structured message"
    event = normalize_line(line)
    assert event["timestamp"].year == 2026
    assert event["timestamp"].tzinfo is None


def test_syslog_catches_non_auth_sshd_lines():
    # SSHParser only claims Failed/Accepted password lines; a disconnect
    # message falls through to the generic syslog wrapper instead of
    # `unparsed`, since it's still a well-formed syslog envelope.
    line = "Aug 28 10:31:15 server sshd[1234]: Connection closed by 203.0.113.5 port 51515"
    event = normalize_line(line)
    assert event["source_type"] == "syslog"
    assert event["parsed_fields"]["tag"] == "sshd"


# ---------- generic ----------

def test_blank_line_returns_none():
    assert normalize_line("   ") is None


def test_unrecognised_line_falls_back_to_generic():
    event = normalize_line("this has no structure whatsoever")
    assert event["event_type"] == "unparsed"
    assert event["category"] == "application"
    assert event["outcome"] == "unknown"
