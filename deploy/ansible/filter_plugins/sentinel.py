# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guard-rail filters for the PoP playbooks (stdlib only, no netaddr).

Lab and production must never mix: production configs may not announce
documentation/private prefixes or use private ASNs, and lab configs may only
use them (spec section 1: lab only until the explicit go-ahead).
"""
import ipaddress

LAB_V4 = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
          "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]
LAB_V6 = ["2001:db8::/32", "fc00::/7"]


def _net(p):
    return ipaddress.ip_network(str(p), strict=True)


def lab_prefix(p):
    """True when the prefix lies inside a documentation or private range."""
    n = _net(p)
    ranges = LAB_V4 if n.version == 4 else LAB_V6
    return any(n.subnet_of(ipaddress.ip_network(r)) for r in ranges)


def private_asn(asn):
    """Private (RFC 6996) or documentation (RFC 5398) ASNs."""
    a = int(asn)
    return 64496 <= a <= 65534 or 4200000000 <= a <= 4294967294 or 65536 <= a <= 65551


def announceable(p):
    """Most networks accept IPv4 up to /24 and IPv6 up to /48."""
    n = _net(p)
    return n.prefixlen <= (24 if n.version == 4 else 48)


def ip_in_any(ip, prefixes):
    a = ipaddress.ip_address(str(ip))
    return any(a in ipaddress.ip_network(str(p), strict=False) for p in prefixes or [])


def valid_prefix(p):
    try:
        _net(p)
        return True
    except ValueError:
        return False


def prefix_version(p):
    return _net(p).version


class FilterModule:
    def filters(self):
        return {
            "sentinel_lab_prefix": lab_prefix,
            "sentinel_private_asn": private_asn,
            "sentinel_announceable": announceable,
            "sentinel_ip_in_any": ip_in_any,
            "sentinel_valid_prefix": valid_prefix,
            "sentinel_prefix_version": prefix_version,
        }
