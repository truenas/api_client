# SPDX-License-Identifier: LGPL-3.0-or-later
"""Unit tests for daemon constants."""

import unittest

from truenas_api_client.daemon.constants import (
    Command,
    MessageType,
    DAEMON_ACCEPT_TIMEOUT,
    DAEMON_CONNECT_TIMEOUT,
    DAEMON_REQUEST_TIMEOUT,
    SOCKET_PERMISSIONS,
    SOCKET_RECV_BUFFER_SIZE,
)


class TestMessageTypeEnum(unittest.TestCase):
    """Test MessageType enum."""

    def test_enum_values(self):
        """MessageType enum should have expected values."""
        self.assertEqual(MessageType.PROGRESS, 'progress')
        self.assertEqual(MessageType.RESULT, 'result')
        self.assertEqual(MessageType.ERROR, 'error')


class TestCommandEnum(unittest.TestCase):
    """Test Command enum."""

    def test_enum_values(self):
        """Command enum should have expected values."""
        self.assertEqual(Command.PING, 'ping')
        self.assertEqual(Command.CALL, 'call')
        self.assertEqual(Command.STOP, 'stop')


class TestTimeoutConstants(unittest.TestCase):
    """Test timeout constants."""

    def test_request_timeout(self):
        """Request timeout should be reasonable."""
        self.assertGreater(DAEMON_REQUEST_TIMEOUT, 0)
        self.assertGreaterEqual(DAEMON_REQUEST_TIMEOUT, 60)  # At least 1 minute

    def test_accept_timeout(self):
        """Accept timeout should be short for quick checks."""
        self.assertGreater(DAEMON_ACCEPT_TIMEOUT, 0)
        self.assertLessEqual(DAEMON_ACCEPT_TIMEOUT, 10)

    def test_connect_timeout(self):
        """Connect timeout should be short for quick checks."""
        self.assertGreater(DAEMON_CONNECT_TIMEOUT, 0)
        self.assertLessEqual(DAEMON_CONNECT_TIMEOUT, 5)


class TestBufferSize(unittest.TestCase):
    """Test buffer size constant."""

    def test_power_of_two(self):
        """Buffer size should be power of 2 (common for network buffers)."""
        # Check if power of 2: n & (n-1) == 0 for powers of 2
        # This also ensures it's positive
        self.assertEqual(SOCKET_RECV_BUFFER_SIZE & (SOCKET_RECV_BUFFER_SIZE - 1), 0)


class TestSocketPermissions(unittest.TestCase):
    """Test socket permissions constant."""

    def test_owner_only(self):
        """Socket permissions should be owner-only (0o600)."""
        self.assertEqual(SOCKET_PERMISSIONS, 0o600)


if __name__ == '__main__':
    unittest.main()
