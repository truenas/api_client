# SPDX-License-Identifier: LGPL-3.0-or-later
"""Unit tests for daemon utility functions."""

import unittest
from unittest.mock import patch

from truenas_api_client.daemon.utils import (
    get_daemon_identifier,
    get_daemon_socket_path,
    get_daemon_pid_path,
)


class TestDaemonIdentifier(unittest.TestCase):
    """Test daemon identifier generation."""

    def test_local_identifier(self):
        """Local connections should use 'local' identifier."""
        self.assertEqual(get_daemon_identifier(uri=None, username=None), "local")
        self.assertEqual(get_daemon_identifier(uri=None, username="admin"), "local")

    def test_deterministic(self):
        """Same URI/username should produce same identifier."""
        uri = "wss://192.168.1.100/api/current"
        username = "admin"

        id1 = get_daemon_identifier(uri, username)
        id2 = get_daemon_identifier(uri, username)

        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 12)  # First 12 chars of SHA256

    def test_unique_combinations(self):
        """Different URI/username combinations should produce different identifiers."""
        uri1 = "wss://192.168.1.100/api/current"
        uri2 = "wss://192.168.1.101/api/current"
        username1 = "admin"
        username2 = "user"

        id_uri1_user1 = get_daemon_identifier(uri1, username1)
        id_uri2_user1 = get_daemon_identifier(uri2, username1)
        id_uri1_user2 = get_daemon_identifier(uri1, username2)

        # All should be different
        self.assertNotEqual(id_uri1_user1, id_uri2_user1)
        self.assertNotEqual(id_uri1_user1, id_uri1_user2)
        self.assertNotEqual(id_uri2_user1, id_uri1_user2)


class TestDaemonPaths(unittest.TestCase):
    """Test daemon path generation."""

    def test_socket_path_format_local(self):
        """Socket path for local connection should use 'local' identifier."""
        with patch('truenas_api_client.daemon.utils.get_daemon_dir', return_value='/tmp/test'):
            path = get_daemon_socket_path(uri=None, username=None)
            self.assertEqual(path, '/tmp/test/daemon-local.sock')

    def test_socket_path_format_remote(self):
        """Socket path for remote connection should have hash identifier."""
        with patch('truenas_api_client.daemon.utils.get_daemon_dir', return_value='/tmp/test'):
            path = get_daemon_socket_path(uri="ws://test/api/current", username="admin")
            self.assertTrue(path.startswith('/tmp/test/daemon-'))
            self.assertTrue(path.endswith('.sock'))
            # Should not be 'local'
            self.assertNotIn('daemon-local', path)

    def test_pid_path_format_local(self):
        """PID path for local connection should use 'local' identifier."""
        with patch('truenas_api_client.daemon.utils.get_daemon_dir', return_value='/tmp/test'):
            path = get_daemon_pid_path(uri=None, username=None)
            self.assertEqual(path, '/tmp/test/daemon-local.pid')

    def test_pid_path_format_remote(self):
        """PID path for remote connection should have hash identifier."""
        with patch('truenas_api_client.daemon.utils.get_daemon_dir', return_value='/tmp/test'):
            path = get_daemon_pid_path(uri="ws://test/api/current", username="admin")
            self.assertTrue(path.startswith('/tmp/test/daemon-'))
            self.assertTrue(path.endswith('.pid'))

    def test_socket_and_pid_paths_match(self):
        """Socket and PID paths should have matching identifiers."""
        uri = "wss://192.168.1.100/api/current"
        username = "admin"

        socket_path = get_daemon_socket_path(uri, username)
        pid_path = get_daemon_pid_path(uri, username)

        # Extract identifiers from paths
        socket_id = socket_path.split('daemon-')[1].split('.sock')[0]
        pid_id = pid_path.split('daemon-')[1].split('.pid')[0]

        self.assertEqual(socket_id, pid_id)


if __name__ == '__main__':
    unittest.main()
