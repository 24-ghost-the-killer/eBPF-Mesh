#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Send crafted Ethernet frames through an AF_PACKET socket.

Used by veth.sh to put malformed / anomalous frames on a veth link that no
normal socket API would emit.

    send_frames.py <iface> <dst_mac> <kind> <count>

kinds: syn, xmas, tcp_trunc, udp_len_bad, ipv6_frag_later

Lab-only: every frame is addressed inside 10.0.0.0/8 or fd00::/8, and the
script refuses to build anything else.
"""
import ipaddress
import socket
import struct
import sys

SRC4 = ipaddress.ip_address("10.99.0.2")
DST4 = ipaddress.ip_address("10.99.0.1")
SRC6 = ipaddress.ip_address("fd00::2")
DST6 = ipaddress.ip_address("fd00::1")
LAB_NETS = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("fd00::/8"))


def lab_only(*addrs) -> None:
    for a in addrs:
        if not any(a in n for n in LAB_NETS if n.version == a.version):
            raise SystemExit(f"refusing to send to non-lab address {a}")


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(proto: int, payload: bytes) -> bytes:
    lab_only(SRC4, DST4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0, 64, proto, 0,
                      SRC4.packed, DST4.packed)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(nexthdr: int, payload: bytes) -> bytes:
    lab_only(SRC6, DST6)
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nexthdr, 64,
                       SRC6.packed, DST6.packed) + payload


def tcp(flags: int) -> bytes:
    return struct.pack("!HHIIBBHHH", 40000, 22, 1, 0, 5 << 4, flags, 65535, 0, 0)


def frame(dst_mac: bytes, src_mac: bytes, ethertype: int, l3: bytes) -> bytes:
    f = dst_mac + src_mac + struct.pack("!H", ethertype) + l3
    return f + b"\0" * max(0, 60 - len(f))  # Ethernet minimum size


def build(kind: str, dst_mac: bytes, src_mac: bytes) -> bytes:
    if kind == "syn":
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, tcp(0x02)))
    if kind == "xmas":  # FIN|PSH|URG
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, tcp(0x29)))
    if kind == "tcp_trunc":  # 10-byte IP payload cannot hold a TCP header
        return frame(dst_mac, src_mac, 0x0800, ipv4(6, b"\x9c\x40\x00\x16" + b"\0" * 6))
    if kind == "udp_len_bad":  # UDP length claims more than the IP payload
        udp = struct.pack("!HHHH", 5353, 53, 200, 0) + b"x" * 12
        return frame(dst_mac, src_mac, 0x0800, ipv4(17, udp))
    if kind == "ipv6_frag_later":
        fh = struct.pack("!BBHI", 17, 0, (100 << 3), 0xABCD)
        return frame(dst_mac, src_mac, 0x86DD, ipv6(44, fh + b"y" * 32))
    raise SystemExit(f"unknown kind {kind}")


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    iface, dst, kind, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    dst_mac = bytes.fromhex(dst.replace(":", ""))
    with open(f"/sys/class/net/{iface}/address") as f:
        src_mac = bytes.fromhex(f.read().strip().replace(":", ""))
    pkt = build(kind, dst_mac, src_mac)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    for _ in range(count):
        s.send(pkt)
    s.close()


if __name__ == "__main__":
    main()
