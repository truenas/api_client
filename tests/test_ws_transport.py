# SPDX-License-Identifier: LGPL-3.0-or-later
"""Live loopback tests for the websockets-based transport.

Runs a fake middleware server (websockets.sync.server) speaking just enough of both
protocols to exercise the full client stack over a real connection: the JSON-RPC 2.0
endpoint at /api/current and the legacy DDP-style endpoint at /websocket. Covers the
contracts the failover consumer depends on (_closed event, in-flight call errors on
disconnect, ClientHandshakeError with status_code 404 for the legacy fallback) plus
behaviors that websockets' defaults would silently change (messages over 1MiB).
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import os
import tempfile
from threading import Thread
import unittest
from unittest import mock
import uuid

from websockets.sync.server import serve, unix_serve

from truenas_api_client import Client, JSONRPCClient, ClientException, transport
from truenas_api_client.exc import ClientHandshakeError
from truenas_api_client.legacy import LegacyClient
from truenas_api_client import ejson as json

BIG_RESULT = 'x' * (2 * 1024 * 1024)  # over websockets' 1MiB default limit


def jsonrpc_handler(conn):
    """Minimal JSON-RPC 2.0 middleware emulation."""
    subscriptions = []
    for raw in conn:
        message = json.loads(raw)
        method, params, msg_id = message['method'], message['params'], message['id']
        if method == 'core.set_options':
            result = {'legacy_jobs': False}
        elif method == 'core.ping':
            result = 'pong'
        elif method == 'core.subscribe':
            result = str(uuid.uuid4())
            subscriptions.append(params[0])
        elif method == 'echo':
            result = params
        elif method == 'big.result':
            result = BIG_RESULT
        elif method == 'server.close':
            conn.close(4000, 'going away')
            return
        elif method == 'server.drop':
            conn.socket.close()  # hard drop, no close frame
            return
        elif method == 'job.echo':
            # New-style job: return the job id as the call result via core.get_jobs
            # collection_update, then complete the job.
            job_id = 1234
            conn.send(json.dumps({
                'jsonrpc': '2.0',
                'method': 'collection_update',
                'params': {
                    'collection': 'core.get_jobs', 'msg': 'added', 'id': job_id,
                    'fields': {'id': job_id, 'message_ids': [msg_id]},
                },
            }))
            conn.send(json.dumps({
                'jsonrpc': '2.0',
                'method': 'collection_update',
                'params': {
                    'collection': 'core.get_jobs', 'msg': 'changed', 'id': job_id,
                    'fields': {'id': job_id, 'message_ids': [msg_id], 'state': 'SUCCESS',
                               'result': params[0], 'progress': {'percent': 100, 'description': 'done'}},
                },
            }))
            continue
        elif method == 'error.method':
            conn.send(json.dumps({
                'jsonrpc': '2.0', 'id': msg_id,
                'error': {'code': -32601, 'message': 'Method does not exist'},
            }))
            continue
        else:
            result = None
        conn.send(json.dumps({'jsonrpc': '2.0', 'id': msg_id, 'result': result}))


def legacy_handler(conn):
    """Minimal legacy (DDP-style) middleware emulation."""
    for raw in conn:
        message = json.loads(raw)
        match message.get('msg'):
            case 'connect':
                conn.send(json.dumps({'msg': 'connected'}))
            case 'ping':
                conn.send(json.dumps({'msg': 'pong', 'id': message['id']}))
            case 'method':
                if message['method'] == 'echo':
                    conn.send(json.dumps({'msg': 'result', 'id': message['id'],
                                          'result': list(message['params'])}))
                elif message['method'] == 'server.close':
                    conn.close(4001, 'legacy going away')
                    return


def routing_handler(conn):
    """Route by handshake path, like the real middleware."""
    if conn.request.path == '/api/current':
        jsonrpc_handler(conn)
    elif conn.request.path == '/websocket':
        legacy_handler(conn)


def reject_unknown_paths(conn, request):
    if request.path not in ('/api/current', '/websocket'):
        return conn.respond(404, 'Not Found\n')


def legacy_only_paths(conn, request):
    """Emulate a pre-25.04 server: /api/current does not exist."""
    if request.path != '/websocket':
        return conn.respond(404, 'Not Found\n')


class TransportTestBase(unittest.TestCase):
    process_request = staticmethod(reject_unknown_paths)

    @classmethod
    def setUpClass(cls):
        cls.server = serve(routing_handler, '127.0.0.1', 0, process_request=cls.process_request)
        Thread(daemon=True, target=cls.server.serve_forever).start()
        port = cls.server.socket.getsockname()[1]
        cls.base_url = f'ws://127.0.0.1:{port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()


class TestJSONRPCTransport(TransportTestBase):
    def _client(self):
        return Client(f'{self.base_url}/api/current')

    def test_connect_call_and_close(self):
        with self._client() as c:
            self.assertEqual(c.ping(), 'pong')
            self.assertEqual(c.call('echo', 1, 'two'), [1, 'two'])

    def test_message_over_1mib(self):
        """websockets' default 1MiB max_size must not apply."""
        with self._client() as c:
            self.assertEqual(c.call('big.result'), BIG_RESULT)

    def test_job_flow(self):
        with self._client() as c:
            self.assertEqual(c.call('job.echo', 42, job=True), 42)

    def test_call_error(self):
        with self._client() as c:
            with self.assertRaises(ClientException) as ctx:
                c.call('error.method')
            self.assertEqual(ctx.exception.errno, ClientException.ENOMETHOD)

    def test_concurrent_calls(self):
        with self._client() as c:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda i: c.call('echo', i), range(64)))
            self.assertEqual(results, [[i] for i in range(64)])

    def test_server_close_sets_closed_and_fails_calls(self):
        """The failover consumer blocks on c._closed and expects in-flight calls to error."""
        c = self._client()
        with self.assertRaises(ClientException) as ctx:
            c.call('server.close')
        self.assertEqual(ctx.exception.errno, errno.ECONNABORTED)
        self.assertIn('4000', str(ctx.exception))
        self.assertTrue(c._closed.wait(5))
        # Subsequent calls fail cleanly rather than hanging
        with self.assertRaises(ClientException):
            c.call('core.ping')

    def test_abnormal_drop_reports_code_none(self):
        """A connection dropped without a close frame reports code=None, like the old transport."""
        c = self._client()
        with self.assertRaises(ClientException) as ctx:
            c.call('server.drop')
        self.assertEqual(ctx.exception.errno, errno.ECONNABORTED)
        self.assertIn('code=None', str(ctx.exception))
        self.assertTrue(c._closed.wait(5))

    def test_handshake_404_raises_client_handshake_error(self):
        with self.assertRaises(ClientHandshakeError) as ctx:
            Client(f'{self.base_url}/api/nonexistent')
        self.assertEqual(ctx.exception.status_code, 404)

    def test_ws_url_attribute_preserved(self):
        """tests/api2/test_legacy_api.py in middleware reads c._ws.url."""
        with self._client() as c:
            self.assertEqual(c._ws.url, f'{self.base_url}/api/current')


class TestLegacyTransport(TransportTestBase):
    def test_connect_call_and_close(self):
        with Client(f'{self.base_url}/websocket') as c:
            # Client.__enter__ yields the wrapped client; a /websocket URI selects LegacyClient
            self.assertIsInstance(c, LegacyClient)
            self.assertTrue(c.ping())
            self.assertEqual(c.call('echo', 'a', 2), ['a', 2])

    def test_server_close_sets_closed(self):
        c = LegacyClient(f'{self.base_url}/websocket')
        with self.assertRaises(ClientException) as ctx:
            c.call('server.close')
        self.assertEqual(ctx.exception.errno, errno.ECONNABORTED)
        self.assertTrue(c._closed.wait(5))


class TestLegacyFallback(TransportTestBase):
    """The failover scenario: a 24.10-or-earlier peer 404s /api/current; the consumer
    falls back to the legacy endpoint, keyed on ClientHandshakeError.status_code."""
    process_request = staticmethod(legacy_only_paths)

    def test_fallback(self):
        url = f'{self.base_url}/api/current'
        try:
            client = Client(url)
        except ClientHandshakeError as e:
            self.assertEqual(e.status_code, 404)
            client = Client(f'{self.base_url}/websocket')
        with client as c:
            self.assertEqual(c.call('echo', 'legacy'), ['legacy'])


class TestReservedPortsTransport(TransportTestBase):
    """The failover heartbeat path: a pre-bound caller-provided socket handed to websockets.

    Binding an actual reserved port needs root, so bind an ephemeral port instead; the
    rest of the code path (raw socket, sock= handoff, handshake over it) is identical.
    """

    @staticmethod
    def _bind_ephemeral(ws):
        ws.socket.bind(('127.0.0.1', 0))

    def test_reserved_path_connects_and_clears_timeout(self):
        with mock.patch.object(transport.WSClient, '_bind_to_reserved_port', self._bind_ephemeral):
            with Client(f'{self.base_url}/api/current', reserved_ports=True) as c:
                self.assertIsNone(c._ws.socket.gettimeout())
                self.assertEqual(c.call('echo', 'ha'), ['ha'])

    def test_reserved_socket_blocking_before_handoff(self):
        """The 10s connect timeout must be cleared BEFORE the socket reaches websockets.

        websockets' reader thread latches the current timeout on its first recv and treats
        the resulting timeout as fatal, so a leftover timeout kills the HA link after 10s
        of idle even if the timeout is cleared right after connect() returns.
        """
        seen = {}
        real_connect = transport.ws_connect

        def spying_connect(url, **kwargs):
            seen['timeout_at_handoff'] = kwargs['sock'].gettimeout()
            return real_connect(url, **kwargs)

        with mock.patch.object(transport, 'ws_connect', spying_connect), \
                mock.patch.object(transport.WSClient, '_bind_to_reserved_port', self._bind_ephemeral):
            with Client(f'{self.base_url}/api/current', reserved_ports=True) as c:
                c.ping()
        self.assertIsNone(seen['timeout_at_handoff'])

    def test_reserved_path_legacy_fallback(self):
        with mock.patch.object(transport.WSClient, '_bind_to_reserved_port', self._bind_ephemeral):
            with Client(f'{self.base_url}/websocket', reserved_ports=True) as c:
                self.assertIsNone(c._ws.socket.gettimeout())
                self.assertEqual(c.call('echo', 'legacy-ha'), ['legacy-ha'])


class TestUnixSocketTransport(unittest.TestCase):
    """The handshake path over a unix socket selects the protocol; verify both routes."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.sock_path = os.path.join(cls.tmpdir.name, 'middlewared.sock')
        cls.server = unix_serve(routing_handler, cls.sock_path, process_request=reject_unknown_paths)
        Thread(daemon=True, target=cls.server.serve_forever).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmpdir.cleanup()

    def test_jsonrpc_over_unix_socket(self):
        with JSONRPCClient(f'ws+unix://{self.sock_path}') as c:
            self.assertEqual(c.ping(), 'pong')

    def test_legacy_over_unix_socket(self):
        with LegacyClient(f'ws+unix://{self.sock_path}') as c:
            self.assertEqual(c.call('echo', 5), [5])

    def test_missing_socket_raises_oserror(self):
        """midclt catches FileNotFoundError to print 'Daemon not running?'."""
        with self.assertRaises(FileNotFoundError):
            JSONRPCClient(f'ws+unix://{self.tmpdir.name}/nonexistent.sock')


class TestConnectionRefused(unittest.TestCase):
    def test_connection_refused_propagates(self):
        """remote.py maps connect-time OSError errnos; ConnectionRefusedError must not be wrapped."""
        with self.assertRaises(ConnectionRefusedError):
            JSONRPCClient('ws://127.0.0.1:1/api/current')


if __name__ == '__main__':
    unittest.main()
