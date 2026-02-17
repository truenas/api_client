"""Client-side functions for communicating with daemon."""
import os
import socket
import sys

from .. import ejson as json
from .constants import (
    DAEMON_CONNECT_TIMEOUT,
    DAEMON_REQUEST_TIMEOUT,
    Command,
    MessageType,
    SOCKET_RECV_BUFFER_SIZE,
)
from .utils import cleanup_stale_files, get_daemon_pid_path, get_daemon_socket_path


def is_daemon_running(uri=None, username=None):
    """Check if a daemon is currently running and responsive.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
    """
    socket_path = get_daemon_socket_path(uri, username)
    pid_path = get_daemon_pid_path(uri, username)

    if not os.path.exists(socket_path):
        return False

    # Check if PID file exists and process is alive
    if os.path.exists(pid_path):
        try:
            with open(pid_path, 'r') as f:
                pid = int(f.read().strip())
            # Check if process exists (signal 0 doesn't kill, just checks)
            os.kill(pid, 0)
        except (OSError, ValueError):
            # Process doesn't exist, clean up stale files
            cleanup_stale_files(uri, username)
            return False

    # Try to connect to verify it's responsive
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DAEMON_CONNECT_TIMEOUT)
        sock.connect(socket_path)
        sock.close()
        return True
    except (socket.error, socket.timeout, AttributeError):
        return False


def send_to_daemon(request_data, uri=None, username=None, progress_callback=None):
    """Send a request to the daemon and receive the response.

    Args:
        request_data: Dictionary containing the request to forward to middleware.
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
        progress_callback: Optional callback function for job progress updates.
            Called with dict containing 'percent', 'description', 'state'.

    Returns:
        The response from middleware (dict with 'type' and either 'result' or 'error').

    Raises:
        Exception: If communication with daemon fails.
    """
    socket_path = get_daemon_socket_path(uri, username)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        sock.settimeout(DAEMON_REQUEST_TIMEOUT)
        sock.connect(socket_path)

        # Send request as JSON
        request_json = json.dumps(request_data) + '\n'
        sock.sendall(request_json.encode('utf-8'))

        # Receive response(s) - may be multiple messages for jobs with progress
        buffer = b''
        while True:
            # Read until we have a complete message (ends with newline)
            while b'\n' not in buffer:
                chunk = sock.recv(SOCKET_RECV_BUFFER_SIZE)
                if not chunk:
                    raise Exception("Daemon closed connection without response")
                buffer += chunk

            # Extract one message
            line, buffer = buffer.split(b'\n', 1)
            if not line:
                continue

            response = json.loads(line.decode('utf-8'))
            msg_type = response.get('type')

            # Handle progress updates
            if msg_type == MessageType.PROGRESS:
                if progress_callback:
                    progress_callback(response)
                continue  # Keep reading for final result

            # Handle result or error (final message)
            elif msg_type in (MessageType.RESULT, MessageType.ERROR):
                return response

            else:
                raise Exception(f"Unknown message type from daemon: {msg_type}")

    finally:
        sock.close()


def stop_daemon(uri=None, username=None):
    """Stop a running daemon.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
    """
    if not is_daemon_running(uri, username):
        print("No daemon is currently running", file=sys.stderr)
        return False

    try:
        response = send_to_daemon({'command': Command.STOP}, uri, username)
        if MessageType.RESULT in response:
            print(response['result'], file=sys.stderr)
            return True
        else:
            print(f"Error stopping daemon: {response.get('error', 'Unknown error')}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"Error communicating with daemon: {e}", file=sys.stderr)
        return False
