#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Send crafted Ethernet frames out of an interface (AF_PACKET, needs root).

LAB ONLY: every destination address must be inside the lab ranges of the
spec (section 11.1) unless --allow-non-lab-destination is given.

Kinds:
  valid4     IPv4/UDP to --dst4
  valid6     IPv6/UDP to --dst6
  vlan4      802.1Q-tagged IPv4/UDP
  qinq6      802.1ad + 802.1Q IPv6/TCP SYN
  frag4      IPv4 non-first fragments
  frag6      IPv6 non-first fragments
  nonip      ethertype 0x88B5 (IEEE local experimental)
  malformed  rotating set of invalid IPv4/IPv6/VLAN frames
"""
import argparse
import ipaddress
import socket
import struct
import sys

LAB_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "198.51.100.0/24",    # anycast (protected IPs)
        "2001:db8:100::/48",  # anycast v6
        "10.10.1.0/24",       # PoP unicast / management
        "192.0.2.0/24",       # customer origins
        "203.0.113.0/24",     # bots
    )
]

ETH_IP, ETH_IP6, ETH_VLAN, ETH_QINQ = 0x0800, 0x86DD, 0x8100, 0x88A8


def mac(s):
    b = bytes(int(x, 16) for x in s.split(":"))
    if len(b) != 6:
        raise argparse.ArgumentTypeError(f"bad MAC {s!r}")
    return b


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Frames:
    def __init__(self, a):
        self.a = a
        self.src4 = ipaddress.IPv4Address(a.src4).packed
        self.dst4 = ipaddress.IPv4Address(a.dst4).packed
        self.src6 = ipaddress.IPv6Address(a.src6).packed
        self.dst6 = ipaddress.IPv6Address(a.dst6).packed

    def eth(self, proto):
        return self.a.dst_mac + self.a.src_mac + struct.pack("!H", proto)

    @staticmethod
    def vlan(vid, proto):
        return struct.pack("!HH", vid & 0xFFF, proto)

    def ip4(self, proto, payload, frag=0, ihl=5, tot=None):
        opts = b"\x01" * (ihl * 4 - 20) if ihl >= 5 else b""
        tot = 20 + len(opts) + len(payload) if tot is None else tot
        h = struct.pack("!BBHHHBBH4s4s", 0x40 | (ihl & 0xF), 0, tot, 0x1234,
                        frag, 64, proto, 0, self.src4, self.dst4) + opts
        h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
        return h + payload

    def ip6(self, nh, payload, plen=None):
        plen = len(payload) if plen is None else plen
        return struct.pack("!IHBB16s16s", 0x60000000, plen, nh, 64,
                           self.src6, self.dst6) + payload

    @staticmethod
    def udp(sport=40000, dport=53, n=16):
        return struct.pack("!HHHH", sport, dport, 8 + n, 0) + b"\0" * n

    @staticmethod
    def tcp(flags=0x02, doff=5):
        h = struct.pack("!HHIIBBHHH", 40000, 443, 1000, 0, doff << 4, flags,
                        64240, 0, 0)
        return h + b"\0" * max(0, doff * 4 - 20)

    # ---- kinds -----------------------------------------------------------
    def valid4(self, i):
        return self.eth(ETH_IP) + self.ip4(17, self.udp(n=16 + i % 8))

    def valid6(self, i):
        return self.eth(ETH_IP6) + self.ip6(17, self.udp(n=16 + i % 8))

    def vlan4(self, i):
        return (self.eth(ETH_VLAN) + self.vlan(100, ETH_IP)
                + self.ip4(17, self.udp()))

    def qinq6(self, i):
        return (self.eth(ETH_QINQ) + self.vlan(200, ETH_VLAN)
                + self.vlan(100, ETH_IP6) + self.ip6(6, self.tcp()))

    def frag4(self, i):
        return self.eth(ETH_IP) + self.ip4(17, b"\0" * 64, frag=100 + i)

    def frag6(self, i):
        fh = struct.pack("!BBHI", 17, 0, (185 + i) << 3, 0xDEADBEEF)
        return self.eth(ETH_IP6) + self.ip6(44, fh + b"\0" * 64)

    def nonip(self, i):
        return self.eth(0x88B5) + b"\0" * 46

    def malformed(self, i):
        variants = [
            # IPv4 with only half a TCP header
            lambda: self.eth(ETH_IP) + self.ip4(6, b"\0" * 10),
            # IPv4 IHL < 5
            lambda: self.eth(ETH_IP) + self.ip4(17, self.udp(), ihl=4)
            + b"\0" * 4,
            # IPv4 total length beyond the frame
            lambda: self.eth(ETH_IP) + self.ip4(17, self.udp(), tot=1400),
            # TCP data offset < 5
            lambda: self.eth(ETH_IP) + self.ip4(6, self.tcp(doff=4) + b"\0" * 4),
            # tiny first fragment (MF set, 8 bytes of TCP)
            lambda: self.eth(ETH_IP) + self.ip4(6, b"\0" * 8, frag=0x2000),
            # IPv6 payload length beyond the frame
            lambda: self.eth(ETH_IP6) + self.ip6(17, self.udp(), plen=1000),
            # three VLAN tags
            lambda: self.eth(ETH_QINQ) + self.vlan(1, ETH_VLAN)
            + self.vlan(2, ETH_VLAN) + self.vlan(3, ETH_IP)
            + self.ip4(17, self.udp()),
        ]
        return variants[i % len(variants)]()


def check_lab(a):
    if a.allow_non_lab_destination:
        print("send_frames: WARNING: lab destination check disabled",
              file=sys.stderr)
        return
    for d in (a.dst4, a.dst6):
        addr = ipaddress.ip_address(d)
        if not any(addr in n for n in LAB_NETS):
            sys.exit(f"send_frames: refusing destination {d}: outside the lab "
                     "ranges (use --allow-non-lab-destination to override)")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iface", required=True)
    p.add_argument("--src-mac", type=mac, default=mac("02:00:00:00:00:01"))
    p.add_argument("--dst-mac", type=mac, default=mac("02:00:00:00:00:02"))
    p.add_argument("--src4", default="203.0.113.7")
    p.add_argument("--dst4", default="198.51.100.10")
    p.add_argument("--src6", default="2001:db8:ffff::7")
    p.add_argument("--dst6", default="2001:db8:100::10")
    p.add_argument("--kind", required=True,
                   choices=["valid4", "valid6", "vlan4", "qinq6", "frag4",
                            "frag6", "nonip", "malformed"])
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--allow-non-lab-destination", action="store_true",
                   help="disable the lab-range safety check (never do this)")
    a = p.parse_args()
    check_lab(a)

    f = Frames(a)
    build = getattr(f, a.kind)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    for i in range(a.count):
        s.send(build(i))
    print(f"sent {a.count} {a.kind} frame(s) on {a.iface}")


if __name__ == "__main__":
    main()
