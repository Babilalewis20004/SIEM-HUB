"""
Offline IP -> country lookup, used to enrich events/alerts with "where did
this source IP originate" and to power the dashboard's country breakdown.

Backed by geoip2fast's bundled country-level dataset -- no MaxMind account,
license key, or per-lookup network call required, so it works the same in
an offline dev environment as in CI. Not persisted on the Event row: a
lookup costs single-digit microseconds against the in-memory dataset (see
docs/ARCHITECTURE.md's GeoIP section), so it's computed wherever a source IP
is serialized rather than stored and risking going stale against a newer
dataset.

The GeoIP2Fast instance parses its ~10MB bundled dataset once at import
(a few hundred ms); reused as a module-level singleton so that cost is
paid once per process, not once per request.
"""
from geoip2fast import GeoIP2Fast

_geoip = GeoIP2Fast()


def lookup_country(ip):
    """Return {"country_code", "country_name"} for a public IP, else None
    (missing IP, private/reserved range, or unresolvable address)."""
    if not ip:
        return None
    result = _geoip.lookup(ip)
    if result.is_private or not result.country_code or result.country_code == "--":
        return None
    return {"country_code": result.country_code, "country_name": result.country_name}
