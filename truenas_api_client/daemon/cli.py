"""CLI helper functions for daemon integration."""
import pprint
import sys

from .. import ejson as json
from ..utils import ProgressBar
from .client import is_daemon_running, send_to_daemon
from .constants import Command, MessageType


def call_via_daemon(args, from_json_func):
    """Execute a midclt call command via the daemon.

    Args:
        args: Parsed command-line arguments.
        from_json_func: Function to parse JSON arguments.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Check if daemon is running
    if not is_daemon_running(uri=args.uri, username=args.username):
        print("Error: No daemon is running. Start one with 'midclt daemon'", file=sys.stderr)
        return 1

    try:
        # Prepare call parameters
        params = list(from_json_func(args.method[1:]))
        kwargs = {}
        if args.timeout:
            kwargs['timeout'] = args.timeout
        if args.job:
            kwargs['job'] = True

        # Set up progress callback if this is a job
        progress_bar = None

        if args.job:
            if args.job_print == 'progressbar':
                progress_bar = ProgressBar()
                progress_bar.__enter__()

                def progress_callback(progress_msg):
                    """Update progress bar with info from daemon."""
                    try:
                        progress_bar.update(
                            progress_msg.get('percent', 0),
                            progress_msg.get('description', '')
                        )
                    except Exception as e:
                        print(f'Failed to update progress bar: {e!s}', file=sys.stderr)
            else:
                lastdesc = ['']  # Use list to avoid nonlocal in nested function

                def progress_callback(progress_msg):
                    """Print job description to stderr if it has changed."""
                    desc = progress_msg.get('description', '')
                    if desc and desc != lastdesc[0]:
                        print(desc, file=sys.stderr)
                        lastdesc[0] = desc
        else:
            progress_callback = None

        # Send to daemon
        response = send_to_daemon({
            'command': Command.CALL,
            'method': args.method[0],
            'params': params,
            'kwargs': kwargs
        }, uri=args.uri, username=args.username, progress_callback=progress_callback)

        # Finish progress bar if we used one
        if progress_bar:
            progress_bar.finish()
            progress_bar.__exit__(None, None, None)

        # Handle response
        if response.get('type') == MessageType.ERROR:
            if not args.quiet:
                print(response['error'], file=sys.stderr)
                if response.get('trace'):
                    print(response['trace'].get('formatted', ''), file=sys.stderr)
                if response.get('extra'):
                    pprint.pprint(response['extra'], stream=sys.stderr)
            return 1

        # Print result
        rv = response['result']
        if isinstance(rv, (int, str)):
            print(rv)
        else:
            print(json.dumps(rv))
        return 0

    except Exception as e:
        if progress_bar:
            progress_bar.__exit__(None, None, None)
        print(f"Error communicating with daemon: {e}", file=sys.stderr)
        return 1


def ping_via_daemon(args):
    """Execute a midclt ping command via the daemon.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Check if daemon is running
    if not is_daemon_running(uri=args.uri, username=args.username):
        print("Error: No daemon is running. Start one with 'midclt daemon'", file=sys.stderr)
        return 1

    try:
        # Send ping to daemon
        response = send_to_daemon({
            'command': 'ping',
            'timeout': getattr(args, 'timeout', 10)
        }, uri=args.uri, username=args.username)

        # Handle response
        if response.get('type') == MessageType.ERROR:
            print(f"Ping failed: {response['error']}", file=sys.stderr)
            return 1

        # Print result
        print(response['result'])
        return 0

    except Exception as e:
        print(f"Error communicating with daemon: {e}", file=sys.stderr)
        return 1
