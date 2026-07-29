# SPDX-License-Identifier: LGPL-3.0-or-later
"""ejson round-trips its supported types, and decodes $date without double-counting sub-second ms."""
import unittest
from datetime import date, datetime, time, timezone
from ipaddress import IPv4Interface, IPv6Interface

from truenas_api_client.ejson import dumps, loads


class TestRoundTrip(unittest.TestCase):
    """dumps() then loads() returns an equal value for each supported type."""

    def test_date(self):
        v = date(2024, 7, 3)
        self.assertEqual(loads(dumps(v)), v)

    def test_datetime(self):
        # the encoder is second-granular (drops microseconds), so round-trip a whole-second value
        v = datetime(2024, 7, 3, 16, 22, 6, tzinfo=timezone.utc)
        self.assertEqual(loads(dumps(v)), v)

    def test_time(self):
        v = time(16, 22, 6)
        self.assertEqual(loads(dumps(v)), v)

    def test_time_with_microseconds(self):
        v = time(16, 22, 6, 500000)
        self.assertEqual(loads(dumps(v)), v)

    def test_time_with_utc_offset(self):
        v = time(16, 22, 6, tzinfo=timezone.utc)
        self.assertEqual(loads(dumps(v)), v)

    def test_set(self):
        v = {1, 2, 3, 'a'}
        self.assertEqual(loads(dumps(v)), v)

    def test_frozenset_decodes_to_set(self):
        self.assertEqual(loads(dumps(frozenset({1, 2, 3}))), {1, 2, 3})

    def test_ipv4_interface(self):
        v = IPv4Interface('192.168.1.10/24')
        self.assertEqual(loads(dumps(v)), v)

    def test_ipv6_interface(self):
        v = IPv6Interface('2001:db8::1/64')
        self.assertEqual(loads(dumps(v)), v)


class TestDateDecode(unittest.TestCase):
    """$date decodes milliseconds since epoch without double-counting the sub-second part."""

    def test_subsecond_milliseconds(self):
        self.assertEqual(
            loads('{"$date": 1500}'),
            datetime(1970, 1, 1, 0, 0, 1, 500000, tzinfo=timezone.utc),
        )

    def test_whole_seconds(self):
        self.assertEqual(
            loads('{"$date": 2000}'),
            datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        )


if __name__ == '__main__':
    unittest.main()
