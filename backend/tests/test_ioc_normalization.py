from app.services.ioc_normalization import (
    normalize_ip, normalize_domain, normalize_url, normalize_hash, validate_indicator, sanitize_text,
)


# ---------- IP ----------

def test_normalize_ip_v4():
    assert normalize_ip("185.10.10.10") == "185.10.10.10"


def test_normalize_ip_v6():
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_normalize_ip_invalid():
    assert normalize_ip("999.999.999.999") is None
    assert normalize_ip("not-an-ip") is None
    assert normalize_ip("") is None


# ---------- Domain ----------

def test_normalize_domain_case_insensitive():
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("EXAMPLE.com") == normalize_domain("example.COM")


def test_normalize_domain_trailing_dot():
    assert normalize_domain("example.com.") == "example.com"


def test_normalize_domain_whitespace():
    assert normalize_domain("  example.com  ") == "example.com"


def test_normalize_domain_invalid():
    assert normalize_domain("") is None
    assert normalize_domain("not a domain") is None


def test_subdomain_does_not_match_parent_domain():
    """Explicit project rule: domain matching is exact, never hierarchical."""
    assert normalize_domain("evil.example.com") != normalize_domain("example.com")


# ---------- URL ----------

def test_normalize_url_lowercases_scheme_and_host():
    assert normalize_url("HTTP://Evil-Example.COM/Path") == "http://evil-example.com/Path"


def test_normalize_url_without_scheme_defaults_to_http():
    assert normalize_url("evil-example.com/malware") == "http://evil-example.com/malware"


def test_normalize_url_invalid():
    assert normalize_url("") is None
    assert normalize_url("   ") is None


# ---------- Hashes ----------

def test_normalize_hash_md5():
    h = "a" * 32
    assert normalize_hash(h.upper(), "md5") == h


def test_normalize_hash_sha1():
    h = "b" * 40
    assert normalize_hash(h, "sha1") == h


def test_normalize_hash_sha256():
    h = "c" * 64
    assert normalize_hash(h, "sha256") == h


def test_normalize_hash_wrong_length_invalid():
    assert normalize_hash("a" * 31, "md5") is None
    assert normalize_hash("a" * 64, "md5") is None


def test_normalize_hash_non_hex_invalid():
    assert normalize_hash("z" * 32, "md5") is None


# ---------- validate_indicator ----------

def test_validate_indicator_unsupported_type():
    ok, error = validate_indicator("mac_address", "00:11:22:33:44:55")
    assert ok is False
    assert "Unsupported" in error


def test_validate_indicator_ip_ok():
    ok, normalized = validate_indicator("ip", "185.10.10.10")
    assert ok is True
    assert normalized == "185.10.10.10"


def test_validate_indicator_domain_ok():
    ok, normalized = validate_indicator("domain", "Malicious-Example.COM.")
    assert ok is True
    assert normalized == "malicious-example.com"


# ---------- sanitize_text (CSV formula injection) ----------

def test_sanitize_text_neutralises_formula_prefix():
    assert sanitize_text("=cmd|'/c calc'!A1").startswith("'=")


def test_sanitize_text_leaves_normal_text_alone():
    assert sanitize_text("Internal Threat Feed") == "Internal Threat Feed"


def test_sanitize_text_handles_none():
    assert sanitize_text(None) is None
