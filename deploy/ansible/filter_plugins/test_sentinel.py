# SPDX-License-Identifier: MIT OR Apache-2.0
"""python3 -m unittest discover -s deploy/ansible/filter_plugins"""
import unittest

import sentinel as s


class Filters(unittest.TestCase):
    def test_lab_prefixes(self):
        for p in ["198.51.100.0/24", "203.0.113.0/25", "10.10.0.0/16", "2001:db8:100::/48"]:
            self.assertTrue(s.lab_prefix(p), p)
        for p in ["185.1.2.0/24", "2a0e:1234::/48"]:
            self.assertFalse(s.lab_prefix(p), p)
        with self.assertRaises(ValueError):
            s.lab_prefix("198.51.100.1/24")  # host bits

    def test_asns(self):
        for a in [64512, 65010, 65534, 64500, 4200000001]:
            self.assertTrue(s.private_asn(a), a)
        for a in [3320, 13335, 200000]:
            self.assertFalse(s.private_asn(a), a)

    def test_announceable(self):
        self.assertTrue(s.announceable("185.1.2.0/24"))
        self.assertFalse(s.announceable("185.1.2.0/25"))
        self.assertTrue(s.announceable("2a0e:1234::/48"))
        self.assertFalse(s.announceable("2a0e:1234::/56"))

    def test_membership(self):
        self.assertTrue(s.ip_in_any("192.168.1.7", ["192.168.1.0/24"]))
        self.assertFalse(s.ip_in_any("192.168.2.7", ["192.168.1.0/24"]))
        self.assertFalse(s.ip_in_any("192.168.2.7", []))


if __name__ == "__main__":
    unittest.main()
