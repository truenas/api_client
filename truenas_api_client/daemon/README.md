# Daemon Module

Persistent connection daemon for `midclt` to reduce authentication overhead.

## Purpose

Each `midclt` invocation creates a new WebSocket connection and authenticates, which has significant overhead. The daemon maintains a persistent authenticated connection that multiple `midclt` calls can reuse via Unix domain sockets.

## Architecture

```
midclt -d call  -->  Daemon Server  -->  Middleware Server
   (IPC via Unix socket)  (WebSocket JSON-RPC)
```

The daemon server runs in a separate process, maintains one authenticated WebSocket connection to middleware, and accepts multiple concurrent client connections via Unix domain socket.

## Modules

### `server.py`
- `DaemonServer`: ThreadingUnixStreamServer with client lock for thread safety
- `DaemonRequestHandler`: Handles client requests, forwards to middleware
- `run_daemon()`: Main server loop with idle timeout

### `client.py`
- `send_to_daemon()`: Send request to daemon, handle streaming responses
- `is_daemon_running()`: Check if daemon is alive
- `stop_daemon()`: Send stop command to daemon

### `cli.py`
- `call_via_daemon()`: Execute midclt call command via daemon
- `ping_via_daemon()`: Execute midclt ping command via daemon
- Progress bar handling for job callbacks

### `utils.py`
- Path generation: `get_daemon_socket_path()`, `get_daemon_pid_path()`
- Identifier generation: SHA256 hash of URI/username

### `constants.py`
- `MessageType`: PROGRESS, RESULT, ERROR
- `Command`: PING, CALL, STOP
- Timeout and buffer size constants

### `log_config.py`
- `setup_daemon_logging()`: Configure logging to file or stderr

## IPC Protocol

Communication uses JSON over Unix domain socket, one message per line.

### Request Format
```json
{
  "command": "call|ping|stop",
  "method": "api.method.name",
  "params": [...],
  "kwargs": {"timeout": 60, "job": true}
}
```

### Response Format

**Simple response:**
```json
{"type": "result", "result": <value>}
{"type": "error", "error": "message", "error_type": "ExceptionClass"}
```

**Job with progress streaming:**
```json
{"type": "progress", "percent": 25, "description": "Starting..."}
{"type": "progress", "percent": 50, "description": "Processing..."}
{"type": "result", "result": <value>}
```

## Socket Paths

- **Local**: `~/.midclt/daemon-local.sock`
- **Remote**: `~/.midclt/daemon-{hash}.sock` (hash = first 12 chars of SHA256 of `uri:username`)
- **PID**: Same pattern with `.pid` extension
- **Logs**: `~/.midclt/logs/daemon-{identifier}.log`

## Thread Safety

The daemon uses a single lock (`client_lock`) to serialize all middleware API calls. This ensures the WebSocket connection is not accessed concurrently, as the underlying `JSONRPCClient` is not thread-safe.

## Lifecycle

1. Daemon starts, authenticates to middleware
2. Binds Unix socket with 0o600 permissions (owner-only)
3. Writes PID file with fsync
4. Accepts connections in threaded mode
5. Each request holds `client_lock` for entire request/response cycle
6. Exits after idle timeout or on SIGTERM/SIGINT

## Limitations

- Unix domain sockets only (Linux/macOS/BSD)
- One daemon per URI/username combination
- Subscription commands not supported via daemon
