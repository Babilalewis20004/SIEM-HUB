from app.services.geoip import lookup_country


def test_lookup_country_public_ip():
    result = lookup_country("8.8.8.8")
    assert result == {"country_code": "US", "country_name": "United States"}


def test_lookup_country_private_ip_returns_none():
    assert lookup_country("192.168.1.50") is None


def test_lookup_country_missing_ip_returns_none():
    assert lookup_country(None) is None
    assert lookup_country("") is None


def test_lookup_country_invalid_ip_returns_none():
    assert lookup_country("not-an-ip") is None
