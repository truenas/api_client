"""WebSocket transport shared by `JSONRPCClient` and `LegacyClient`.

Built on `websockets.sync` (thread-based). The transport owns the connection
lifecycle: it establishes the connection (over a unix socket, a raw socket bound
to a reserved port, or plain TCP/TLS), then pumps received messages into the
owning client from a dedicated reader thread via `client._recv()`, and reports
connection closure via `client.on_close(code, reason)`.
"""
import logging
import random
import socket
import ssl
import time
import urllib.parse
from threading import Thread

from websockets.exceptions import ConnectionClosed, InvalidStatus
from websockets.frames import CloseCode
from websockets.sync.client import connect as ws_connect, unix_connect as ws_unix_connect

from . import ejson as json
from .exc import ClientException, ClientHandshakeError, ReserveFDException
from .utils import set_socket_options

logger = logging.getLogger(__name__)

UNIX_SOCKET_PREFIX = "ws+unix://"


class WSClient:
    """Manages the WebSocket connection to the server for a `JSONRPCClient` or `LegacyClient`.

    The object used by the owning client to send and receive data.

    """
    def __init__(self, url: str, *, client, reserved_ports: bool = False, verify_ssl: bool = True,
                 unix_ws_path: str = '/api/current'):
        """Initialize a `WSClient`. Performs no I/O until `connect()` is called.

        Args:
            url: The websocket to connect to. `ws://` or `wss://` for secure connection,
                or `ws+unix://` followed by a filesystem path for a local unix socket.
            client: Reference to the client instance that uses this object.
            reserved_ports: `True` if the `socket` should bind to a reserved port, i.e. 600-1024.
            verify_ssl: `True` if SSL certificate should be verified before connecting.
            unix_ws_path: Resource path requested in the handshake over a unix socket, where the
                URL itself carries no path. Selects the server protocol: `/api/current` for
                JSON-RPC 2.0, `/websocket` for the legacy protocol.

        """
        self.url = url
        self.client = client
        self.reserved_ports = reserved_ports
        self.verify_ssl = verify_ssl
        self.unix_ws_path = unix_ws_path

        self.socket: socket.socket | None = None
        self.conn = None
        self._closing = False

    def connect(self):
        """Establish the connection and start the reader thread.

        Raises:
            ClientException: `reserved_ports` was requested with a non-`ws://` URI.
            ClientHandshakeError: The server rejected the WebSocket handshake with an
                HTTP error status (e.g. 404 from a server without this endpoint).
            ReserveFDException: Failed to bind to a reserved port.
            OSError: The underlying connection failed (includes `ConnectionRefusedError`,
                `FileNotFoundError` for a missing unix socket, `TimeoutError`, and
                `ssl.SSLCertVerificationError`).

        """
        options = {
            # Parity with the previous websocket-client transport: no message size cap,
            # no client keepalive pings, no permessage-deflate, no proxies (not even from
            # proxy environment variables -- the HA heartbeat link must connect directly),
            # and the same 10s/3s connect/close timeout discipline.
            'max_size': None,
            'ping_interval': None,
            'compression': None,
            'proxy': None,
            'open_timeout': 10,
            'close_timeout': 3,
            'legacy': True,
        }

        try:
            if self.url.startswith(UNIX_SOCKET_PREFIX):
                conn = ws_unix_connect(
                    self.url.removeprefix(UNIX_SOCKET_PREFIX),
                    uri=f'ws://localhost{self.unix_ws_path}',
                    **options,
                )
            elif self.reserved_ports:
                # reserved_ports uses a raw socket and never negotiates TLS, so it only supports a
                # plaintext ws:// URI. Require that scheme explicitly rather than, for example,
                # connecting a wss:// URI in cleartext.
                parsed = urllib.parse.urlparse(self.url)
                if parsed.scheme != 'ws':
                    raise ClientException(
                        f'reserved_ports connections require a ws:// URI, got {parsed.scheme!r}'
                    )
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self._bind_to_reserved_port()
                try:
                    self.socket.connect((parsed.hostname, parsed.port or 80))
                except Exception:
                    self.socket.close()
                    raise
                # Return the socket to blocking mode before websockets starts reading from
                # it: its reader thread latches the current timeout on its first recv and
                # treats the resulting timeout as fatal, which would kill the connection
                # after 10s of idle. The WebSocket handshake stays bounded by open_timeout.
                self.socket.settimeout(None)
                conn = ws_connect(self.url, sock=self.socket, **options)
            else:
                ssl_context = None
                if urllib.parse.urlparse(self.url).scheme == 'wss' and not self.verify_ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                conn = ws_connect(self.url, ssl=ssl_context, **options)
        except InvalidStatus as e:
            status_code = e.response.status_code
            raise ClientHandshakeError(
                f'Server rejected WebSocket handshake with HTTP status {status_code}', status_code
            ) from e

        self.conn = conn
        self.socket = conn.socket

        # TCP keepalive settings don't apply to local unix sockets
        if not self.url.startswith(UNIX_SOCKET_PREFIX):
            set_socket_options(self.socket)

        self.client.on_open()

        Thread(daemon=True, target=self._reader, name='truenas_api_client.reader').start()

    def get_peer_cert_der(self) -> bytes | None:
        """Return the server's TLS certificate in DER form, or `None` for a non-TLS
        transport (unix socket, plain `ws://`, or reserved-port connection).

        Used to compute the RFC 5929 tls-server-end-point SCRAM channel binding. The
        certificate is retrievable even when `verify_ssl` is `False`.

        Precondition: the TLS handshake must be complete -- true for the SCRAM login
        flow, which runs after `connect()`. Before the handshake `getpeercert()` returns
        an empty value, which callers treat as "no certificate" (a falsy result).
        """
        sock = getattr(self, 'socket', None)
        if isinstance(sock, ssl.SSLSocket):
            return sock.getpeercert(binary_form=True)

        return None

    def send(self, data: bytes | str):
        """Send data to the server.

        Args:
            data: The serialized request to send.

        Raises:
            websockets.exceptions.ConnectionClosed: The connection is already closed.

        """
        return self.conn.send(data)

    def close(self):
        """Cleanly close the WebSocket connection to the server."""
        # Stop dispatching buffered messages first: websockets' receive buffer may still
        # hold messages that the reader would otherwise deliver after on_close() below
        # has already failed all pending calls and torn down the client.
        self._closing = True
        self.conn.close()
        self.client.on_close(int(CloseCode.NORMAL_CLOSURE))

    def _bind_to_reserved_port(self):
        """Bind to a random port in the 600-1024 range.

        Raises:
            ReserveFDException: Five failed attempts with different ports.

        """
        # linux doesn't have a mechanism to allow the kernel to dynamically
        # assign ports in the "privileged" range (i.e. 600 - 1024) so we
        # loop through and call bind() on a privileged port explicitly since
        # middlewared runs as root.

        # generate 5 random numbers in the `port_low`, `port_high` range
        # so that we guarantee we use a different port from the last
        # iteration in the for loop
        port_low = 600
        port_high = 1024

        ports_to_try = random.sample(range(port_low, port_high), 5)

        for port in ports_to_try:
            try:
                self.socket.bind(('', port))
                return
            except OSError:
                time.sleep(0.1)
                continue

        raise ReserveFDException()

    def _reader(self):
        """Receive messages until the connection closes, dispatching each to the client.

        Runs in a daemon thread. On closure, reports the close code and reason received
        from the server, or `(None, None)` if the connection dropped without a close frame.
        """
        code = reason = None
        try:
            while True:
                data = self.conn.recv()
                if self._closing:
                    continue
                try:
                    self.client._recv(json.loads(data))
                except Exception:
                    logger.exception('Unhandled exception dispatching message')
        except ConnectionClosed as e:
            if e.rcvd is not None:
                code, reason = e.rcvd.code, e.rcvd.reason
        except Exception:
            logger.warning('Unhandled exception in WSClient reader', exc_info=True)

        self.client.on_close(code, reason)
