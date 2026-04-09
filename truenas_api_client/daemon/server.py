"""Daemon server implementation."""
import logging
import os
import signal
import socket
import socketserver
import sys
import time
from threading import Event, Lock
from typing import cast

from .. import ejson as json
from ..exc import ClientException
from .constants import (
    DAEMON_ACCEPT_TIMEOUT,
    Command,
    MessageType,
    SOCKET_PERMISSIONS,
)
from .utils import cleanup_stale_files, get_daemon_pid_path, get_daemon_socket_path

logger = logging.getLogger(__name__)


class DaemonRequestHandler(socketserver.StreamRequestHandler):
    """Handler for daemon client requests."""

    def handle(self):
        """Process a single request from a client."""
        server = cast(DaemonServer, self.server)
        try:
            # Update last activity time (using monotonic for timeout tracking)
            server.last_activity = time.monotonic()

            # Read request (one line of JSON)
            request_line = self.rfile.readline().decode('utf-8').strip()
            if not request_line:
                return

            request = json.loads(request_line)
            command = request.get('command')

            logger.debug("Received command: %s", command)

            # Get the authenticated client from the server
            client = server.client

            # Serialize all client operations to ensure thread safety
            # Hold lock for entire request/response cycle on the websocket
            with server.client_lock:
                # Handle different commands
                if command == Command.PING:
                    try:
                        result = client.ping(timeout=request.get('timeout', 10))
                        response = {'type': MessageType.RESULT, 'result': result}
                    except Exception as e:
                        logger.error("Ping failed: %s", e)
                        response = {'type': MessageType.ERROR, 'error': str(e), 'error_type': type(e).__name__}

                elif command == Command.CALL:
                    method = request['method']
                    params = request.get('params', [])
                    kwargs = request.get('kwargs', {})
                    is_job = kwargs.get('job', False)

                    logger.debug("Calling method: %s (job=%s)", method, is_job)

                    try:
                        # For jobs, set up progress callback to stream updates
                        if is_job:
                            def job_callback(job_dict):
                                """Send job progress updates to client."""
                                try:
                                    progress_msg = json.dumps({
                                        'type': MessageType.PROGRESS,
                                        'percent': job_dict.get('progress', {}).get('percent', 0),
                                        'description': job_dict.get('progress', {}).get('description', ''),
                                        'state': job_dict.get('state', ''),
                                    }) + '\n'
                                    self.wfile.write(progress_msg.encode('utf-8'))
                                    self.wfile.flush()
                                except Exception as e:
                                    logger.error("Error sending progress update: %s", e)

                            kwargs['callback'] = job_callback

                        result = client.call(method, *params, **kwargs)
                        response = {'type': MessageType.RESULT, 'result': result}
                    except ClientException as e:
                        logger.error("Call to %s failed: %s", method, e)
                        response = {
                            'type': MessageType.ERROR,
                            'error': e.error or str(e),
                            'error_type': 'ClientException',
                            'trace': e.trace,
                            'extra': e.extra,
                        }
                    except Exception as e:
                        logger.error("Call to %s failed: %s", method, e, exc_info=True)
                        response = {
                            'type': MessageType.ERROR,
                            'error': str(e),
                            'error_type': type(e).__name__,
                        }

                elif command == Command.STOP:
                    logger.info("Received stop command")
                    response = {'type': MessageType.RESULT, 'result': 'Daemon shutting down'}
                    # Send response before shutting down
                    response_json = json.dumps(response) + '\n'
                    self.wfile.write(response_json.encode('utf-8'))
                    self.wfile.flush()
                    # Trigger shutdown
                    server.shutdown_event.set()
                    return

                else:
                    logger.warning("Unknown command: %s", command)
                    response = {
                        'type': MessageType.ERROR,
                        'error': f'Unknown command: {command}',
                        'error_type': 'ValueError'
                    }

            # Send response (outside lock, but inside try block)
            response_json = json.dumps(response) + '\n'
            self.wfile.write(response_json.encode('utf-8'))
            self.wfile.flush()

        except Exception as e:
            logger.error("Error handling request: %s", e, exc_info=True)
            # Send error response
            try:
                error_response = json.dumps({
                    'type': MessageType.ERROR,
                    'error': str(e),
                    'error_type': type(e).__name__,
                }) + '\n'
                self.wfile.write(error_response.encode('utf-8'))
                self.wfile.flush()
            except Exception:
                pass


class DaemonServer(socketserver.ThreadingUnixStreamServer):
    """Unix socket server for the midclt daemon."""

    def __init__(self, socket_path, client, lifetime):
        """Initialize the daemon server.

        Args:
            socket_path: Path to Unix socket.
            client: Authenticated Client instance.
            lifetime: Idle timeout in seconds (0 = no timeout).
        """
        self.client = client
        self.client_lock = Lock()  # Serialize all client operations
        self.lifetime = lifetime
        self.last_activity = time.monotonic()
        self.shutdown_event = Event()

        super().__init__(socket_path, DaemonRequestHandler)


def run_daemon(client, lifetime, uri=None, username=None, log_file=None):
    """Run the daemon server that forwards requests to middleware.

    Args:
        client: Authenticated Client instance with persistent connection.
        lifetime: Maximum idle time in seconds before daemon exits (0 = no timeout).
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
        log_file: Path to log file (for stdout message).

    Raises:
        OSError: Platform does not support Unix domain sockets.
    """
    # Check if platform supports Unix domain sockets
    if not hasattr(socket, 'AF_UNIX'):
        raise OSError("Unix domain sockets not supported on this platform")

    # Additional platform check for better error messages
    if sys.platform not in ('linux', 'darwin', 'freebsd', 'openbsd', 'netbsd'):
        # Still allow it if AF_UNIX exists (e.g., newer Windows), but warn about potential issues
        logger.warning("Daemon mode on %s is experimental", sys.platform)

    socket_path = get_daemon_socket_path(uri, username)
    pid_path = get_daemon_pid_path(uri, username)

    # Clean up any stale socket
    cleanup_stale_files(uri, username)

    # Write PID file with proper flushing and syncing
    with open(pid_path, 'w') as f:
        f.write(str(os.getpid()))
        f.flush()
        os.fsync(f.fileno())

    try:
        # Create server
        server = DaemonServer(socket_path, client, lifetime)

        # Set permissions so only user can connect (Unix only)
        if hasattr(os, 'chmod'):
            os.chmod(socket_path, SOCKET_PERMISSIONS)

        logger.info("Daemon started with PID %d", os.getpid())
        logger.info("Socket: %s", socket_path)
        if lifetime > 0:
            logger.info("Idle timeout: %d seconds", lifetime)
        else:
            logger.info("Idle timeout: disabled")

        # Print to stdout for user visibility
        if log_file:
            print(f"Accepting connections. Log file: {log_file}", flush=True)
        else:
            print("Accepting connections. Logging to stderr.", flush=True)

        # Signal handler for graceful shutdown
        def signal_handler(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            server.shutdown_event.set()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Main loop: serve requests and check for timeout
        server.timeout = DAEMON_ACCEPT_TIMEOUT

        while not server.shutdown_event.is_set():
            server.handle_request()

            # Check idle timeout (using monotonic time)
            if lifetime > 0 and (time.monotonic() - server.last_activity) > lifetime:
                logger.info("Idle timeout of %d seconds exceeded, shutting down", lifetime)
                break

    finally:
        # Cleanup
        try:
            server.server_close()
        except Exception as e:
            logger.error("Error closing server: %s", e)
        cleanup_stale_files(uri, username)
        logger.info("Daemon stopped")
