# SPDX-License-Identifier: LGPL-3.0-or-later
"""Regression tests: reserved_ports must never silently downgrade a wss:// URI to plaintext.

The reserved-port connection path opens a raw AF_INET socket and hands WebSocketApp a plaintext
dummy ws:// URL, so it never negotiates TLS. Combining it with a wss:// URI used to connect in
cleartext while ignoring verify_ssl; it must now fail closed instead. Both the modern JSON-RPC
client and the legacy client share this path, so both are covered here.
"""
import sys
import unittest
from unittest import mock

from truenas_api_client import WSClient
from truenas_api_client.legacy import WSClient as LegacyWSClient
from truenas_api_client.exc import ClientException

WS_CLIENT_CLASSES = (WSClient, LegacyWSClient)


class _ReachedBind(Exception):
    """Sentinel: raised in place of _bind_to_reserved_port to prove the TLS guard was passed."""


class TestReservedPortsTLS(unittest.TestCase):
    def test_wss_uri_is_refused(self):
        """wss:// + reserved_ports raises ClientException instead of downgrading to plaintext."""
        for cls in WS_CLIENT_CLASSES:
            with self.subTest(client=cls.__module__):
                ws = cls('wss://nas.example.com/api/current', client=None, reserved_ports=True)
                with self.assertRaises(ClientException) as ctx:
                    ws.connect()
                self.assertIn('reserved_ports', str(ctx.exception))

    def test_wss_refused_even_with_verify_ssl_false(self):
        """The refusal keys off the wss:// scheme, so verify_ssl=False cannot re-enable the downgrade."""
        for cls in WS_CLIENT_CLASSES:
            with self.subTest(client=cls.__module__):
                ws = cls('wss://nas.example.com/api/current', client=None, reserved_ports=True,
                         verify_ssl=False)
                with self.assertRaises(ClientException):
                    ws.connect()

    def test_plaintext_ws_passes_the_guard(self):
        """ws:// + reserved_ports (the failover use case) is still allowed through to the bind step."""
        for cls in WS_CLIENT_CLASSES:
            with self.subTest(client=cls.__module__):
                ws = cls('ws://nas.example.com:6000/api/current', client=None, reserved_ports=True)
                module = sys.modules[cls.__module__]
                # Avoid real network I/O: fake the socket and stop at the bind step. If the guard
                # wrongly rejected ws://, we'd see ClientException instead of _ReachedBind.
                with mock.patch.object(module.socket, 'socket', return_value=mock.MagicMock()), \
                        mock.patch.object(ws, '_bind_to_reserved_port', side_effect=_ReachedBind):
                    with self.assertRaises(_ReachedBind):
                        ws.connect()


if __name__ == '__main__':
    unittest.main()
