"""Logging configuration for daemon."""
import logging
import os
import sys


def setup_daemon_logging(log_file=None, uri=None, username=None):
    """Set up logging for daemon process.

    Args:
        log_file: Optional path to log file. If None, defaults to daemon log directory.
        uri: The middleware URI (for default log file naming).
        username: Optional username (for default log file naming).

    Returns:
        str: The log file path being used.
    """
    from .utils import get_daemon_dir, get_daemon_identifier

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if log_file is None:
        # Default to log file in daemon directory
        daemon_dir = get_daemon_dir()
        log_dir = os.path.join(daemon_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        identifier = get_daemon_identifier(uri, username)
        log_file = os.path.join(log_dir, f'daemon-{identifier}.log')

    try:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Logging to %s", log_file)
        return log_file
    except (OSError, PermissionError) as e:
        # Fall back to stderr if we can't write to file
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.error("Failed to open log file %s: %s. Logging to stderr.", log_file, e)
        return None
