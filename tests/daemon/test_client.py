# SPDX-License-Identifier: LGPL-3.0-or-later
"""Unit tests for daemon client message parsing."""

import json
import unittest
from unittest.mock import patch

from truenas_api_client.daemon.client import send_to_daemon
from truenas_api_client.daemon.constants import MessageType, Command


class MockSocket:
    """Mock socket that returns predefined responses."""

    def __init__(self, responses):
        """Initialize with list of response strings to return."""
        self.responses = responses
        self.response_index = 0
        self.sent_data = []
        self.closed = False

    def connect(self, path):
        """Mock connect."""
        pass

    def settimeout(self, timeout):
        """Mock settimeout."""
        pass

    def sendall(self, data):
        """Mock sendall - record what was sent."""
        self.sent_data.append(data)

    def recv(self, bufsize):
        """Mock recv - return next chunk of response."""
        if self.response_index < len(self.responses):
            data = self.responses[self.response_index]
            self.response_index += 1
            return data
        return b''  # EOF

    def close(self):
        """Mock close."""
        self.closed = True


class TestMessageParsing(unittest.TestCase):
    """Test message parsing logic."""

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_simple_result_message(self, mock_path, mock_socket_class):
        """Test parsing a simple result message."""
        response = {'type': MessageType.RESULT, 'result': 'pong'}
        response_bytes = (json.dumps(response) + '\n').encode('utf-8')

        mock_sock = MockSocket([response_bytes])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        result = send_to_daemon({'command': Command.PING})

        self.assertEqual(result['type'], MessageType.RESULT)
        self.assertEqual(result['result'], 'pong')
        self.assertTrue(mock_sock.closed)

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_error_message(self, mock_path, mock_socket_class):
        """Test parsing an error message."""
        response = {
            'type': MessageType.ERROR,
            'error': 'Something went wrong',
            'error_type': 'ValueError'
        }
        response_bytes = (json.dumps(response) + '\n').encode('utf-8')

        mock_sock = MockSocket([response_bytes])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        result = send_to_daemon({'command': Command.CALL})

        self.assertEqual(result['type'], MessageType.ERROR)
        self.assertEqual(result['error'], 'Something went wrong')
        self.assertTrue(mock_sock.closed)

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_progress_then_result(self, mock_path, mock_socket_class):
        """Test parsing progress messages followed by result."""
        progress1 = {
            'type': MessageType.PROGRESS,
            'percent': 50,
            'description': 'Halfway there'
        }
        progress2 = {
            'type': MessageType.PROGRESS,
            'percent': 100,
            'description': 'Complete'
        }
        result = {'type': MessageType.RESULT, 'result': True}

        # Send as separate chunks
        responses = [
            (json.dumps(progress1) + '\n').encode('utf-8'),
            (json.dumps(progress2) + '\n').encode('utf-8'),
            (json.dumps(result) + '\n').encode('utf-8'),
        ]

        mock_sock = MockSocket(responses)
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        progress_updates = []

        def progress_callback(msg):
            progress_updates.append(msg)

        final_result = send_to_daemon(
            {'command': Command.CALL},
            progress_callback=progress_callback
        )

        # Should have received 2 progress updates
        self.assertEqual(len(progress_updates), 2)
        self.assertEqual(progress_updates[0]['percent'], 50)
        self.assertEqual(progress_updates[1]['percent'], 100)

        # Final result should be the result message
        self.assertEqual(final_result['type'], MessageType.RESULT)
        self.assertEqual(final_result['result'], True)

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_progress_without_callback(self, mock_path, mock_socket_class):
        """Test that progress messages are skipped when no callback provided."""
        progress = {
            'type': MessageType.PROGRESS,
            'percent': 50,
            'description': 'Halfway'
        }
        result = {'type': MessageType.RESULT, 'result': 'done'}

        responses = [
            (json.dumps(progress) + '\n').encode('utf-8'),
            (json.dumps(result) + '\n').encode('utf-8'),
        ]

        mock_sock = MockSocket(responses)
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        # No callback provided - progress should be skipped
        final_result = send_to_daemon({'command': Command.CALL})

        self.assertEqual(final_result['type'], MessageType.RESULT)
        self.assertEqual(final_result['result'], 'done')

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_chunked_message(self, mock_path, mock_socket_class):
        """Test parsing a message received in multiple chunks."""
        result = {'type': MessageType.RESULT, 'result': 'test'}
        result_str = json.dumps(result) + '\n'
        result_bytes = result_str.encode('utf-8')

        # Split into multiple chunks
        chunk1 = result_bytes[:10]
        chunk2 = result_bytes[10:20]
        chunk3 = result_bytes[20:]

        mock_sock = MockSocket([chunk1, chunk2, chunk3])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        final_result = send_to_daemon({'command': Command.PING})

        self.assertEqual(final_result['type'], MessageType.RESULT)
        self.assertEqual(final_result['result'], 'test')

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_multiple_messages_in_one_chunk(self, mock_path, mock_socket_class):
        """Test parsing when multiple messages arrive in one chunk."""
        progress = {'type': MessageType.PROGRESS, 'percent': 50}
        result = {'type': MessageType.RESULT, 'result': 'done'}

        # Both messages in one chunk
        combined = (json.dumps(progress) + '\n' + json.dumps(result) + '\n').encode('utf-8')

        mock_sock = MockSocket([combined])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        progress_updates = []

        final_result = send_to_daemon(
            {'command': Command.CALL},
            progress_callback=lambda m: progress_updates.append(m)
        )

        # Should have parsed both messages correctly
        self.assertEqual(len(progress_updates), 1)
        self.assertEqual(final_result['type'], MessageType.RESULT)

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_unknown_message_type(self, mock_path, mock_socket_class):
        """Test handling of unknown message type."""
        response = {'type': 'unknown_type', 'data': 'something'}
        response_bytes = (json.dumps(response) + '\n').encode('utf-8')

        mock_sock = MockSocket([response_bytes])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        with self.assertRaises(Exception) as ctx:
            send_to_daemon({'command': Command.PING})

        self.assertIn('Unknown message type', str(ctx.exception))

    @patch('truenas_api_client.daemon.client.socket.socket')
    @patch('truenas_api_client.daemon.client.get_daemon_socket_path')
    def test_connection_closed_prematurely(self, mock_path, mock_socket_class):
        """Test handling when daemon closes connection without sending response."""
        # Return empty bytes immediately (connection closed)
        mock_sock = MockSocket([b''])
        mock_socket_class.return_value = mock_sock
        mock_path.return_value = '/tmp/test.sock'

        with self.assertRaises(Exception) as ctx:
            send_to_daemon({'command': Command.PING})

        self.assertIn('closed connection without response', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
