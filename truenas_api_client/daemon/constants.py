"""Constants and enums for daemon functionality."""
from enum import StrEnum


class MessageType(StrEnum):
    """Types of messages in daemon IPC protocol."""
    PROGRESS = 'progress'
    RESULT = 'result'
    ERROR = 'error'


class Command(StrEnum):
    """Commands that can be sent to the daemon."""
    PING = 'ping'
    CALL = 'call'
    STOP = 'stop'


# Timeout constants (in seconds)
DAEMON_REQUEST_TIMEOUT = 300  # 5 minutes for long operations
DAEMON_ACCEPT_TIMEOUT = 1.0  # Check for shutdown/timeout every second
DAEMON_CONNECT_TIMEOUT = 1  # Quick check if daemon is running

# Buffer sizes
SOCKET_RECV_BUFFER_SIZE = 4096

# File permissions
SOCKET_PERMISSIONS = 0o600  # Only user can access
