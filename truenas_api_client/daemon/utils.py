"""Utility functions for daemon paths and identifiers."""
import hashlib
import os


def get_daemon_dir():
    """Get the directory for daemon socket and PID file."""
    daemon_dir = os.path.expanduser('~/.midclt')
    os.makedirs(daemon_dir, exist_ok=True)
    return daemon_dir


def get_daemon_identifier(uri=None, username=None):
    """Get unique identifier for daemon based on connection parameters.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.

    Returns:
        A unique identifier string for this daemon configuration.
    """
    if uri is None:
        return "local"

    # Create unique identifier from URI and username
    key = f"{uri}:{username}" if username else uri
    hash_digest = hashlib.sha256(key.encode()).hexdigest()
    return hash_digest[:12]  # Use first 12 chars for reasonable uniqueness


def get_daemon_socket_path(uri=None, username=None):
    """Get the path to the daemon Unix socket.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
    """
    identifier = get_daemon_identifier(uri, username)
    return os.path.join(get_daemon_dir(), f'daemon-{identifier}.sock')


def get_daemon_pid_path(uri=None, username=None):
    """Get the path to the daemon PID file.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
    """
    identifier = get_daemon_identifier(uri, username)
    return os.path.join(get_daemon_dir(), f'daemon-{identifier}.pid')


def cleanup_stale_files(uri=None, username=None):
    """Remove stale socket and PID files.

    Args:
        uri: The middleware URI (None for local).
        username: Optional username for the connection.
    """
    try:
        os.unlink(get_daemon_socket_path(uri, username))
    except OSError:
        pass
    try:
        os.unlink(get_daemon_pid_path(uri, username))
    except OSError:
        pass
