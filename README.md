<p align="center">
      <a href="https://discord.gg/Q3St5fPETd"><img alt="Join Discord" src="https://badgen.net/discord/members/Q3St5fPETd/?icon=discord&label=Join%20the%20TrueNAS%20Community" /></a>
 <a href="https://www.truenas.com/community/"><img alt="Join Forums" src="https://badgen.net/badge/Forums/Post%20Now//purple" /></a> 
 <a href="https://jira.ixsystems.com"><img alt="File Issue" src="https://badgen.net/badge/Jira/File%20Issue//red?icon=jira" /></a>
</p>

# TrueNAS Websocket Client

*Found an issue? Please report it on our [Jira bugtracker](https://jira.ixsystems.com).*

## About

The TrueNAS websocket client provides the command line tool `midclt` and the means to easily communicate with [middleware](https://github.com/truenas/middleware) using Python by making calls through the [websocket API](https://api.truenas.com/). The client can connect to a local TrueNAS instance by default or to a specified remote socket. This offers an alternative to going through the [web UI](https://github.com/truenas/webui) or connecting via ssh.

By default, communication facilitated by the API between the client and middleware now uses the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) protocol. However, it is still possible to use the [legacy client](https://www.truenas.com/docs/api/scale_websocket_api.html) by passing a legacy uri, e.g. `'ws://some.truenas.address/websocket'` as opposed to `'ws://some.truenas.address/api/current'`.

## Getting Started

TrueNAS comes with this client preinstalled, but it is also possible to use the TrueNAS websocket client from a non-TrueNAS host.

**Important:** The `master` branch of this repository is unstable and under active development. For production use, you should install a version that matches your TrueNAS server's version (ideally) or the most recent TrueNAS stable release. Stable releases are indicated by git tags (e.g., `TS-25.10.1`, `TS-25.04.2.6`, `TS-24.10.2.4`).

On a non-TrueNAS host, ensure that Git is installed and run `pip install git+https://github.com/truenas/api_client.git@<tag>` (e.g., `pip install git+https://github.com/truenas/api_client.git@TS-25.10.1`) to install a specific stable version. You may alternatively clone this repository, checkout the appropriate tag, and run `pip install .`. Using a Python venv is recommended. Using `pipx` will automatically create a venv for you (i.e. `pipx install .`).

## Usage

### Console

The `midclt` command (not to be confused with the [TrueNAS CLI](https://github.com/truenas/midcli)) provides a way to make direct API calls through the client. To view its syntax, enter `midclt -h`. The `-h` option can also be used with any of `midclt`'s subcommands.

The client's default behavior is to connect to the localhost's middlewared socket. For a remote connection, e.g. from a Windows host, you must specify the `--uri` option and authenticate with either user credentials or an API key. For example: `midclt --uri ws://<TRUENAS_IP>/api/current -K key ...`

**Note on Performance:** Each `midclt` command invocation incurs significant authentication and auditing overhead. Workloads that poll API endpoints or call endpoints frequently should use the Python API client directly with a persistent authenticated websocket connection (see [Scripting](#scripting) section below) rather than repeatedly invoking `midclt`.

#### Disable SSL certificate verification

The `--insecure` option disables SSL certificate verification when connecting to a remote TrueNAS instance. This is useful for development or testing environments with self-signed certificates.

**WARNING: The `--insecure` option should not be used in production environments as it increases vulnerability to man-in-the-middle attacks.**

```bash
# Only use for development/testing
midclt --uri wss://test.truenas.local/api/current --insecure -K /home/bob/truenas_api_key.json call smb.config
```

#### Make local API calls

```
root@my_truenas[~]# midclt call user.create '{"full_name": "John Doe", "username": "user", "password": "pass", "group_create": true}'
```

#### Login to a remote TrueNAS

```
root@my_truenas[~]# midclt --uri ws://some.other.truenas/api/current -U user -P password call system.info
```

#### Start a job

```
root@my_truenas[~]# midclt call -j pool.dataset.lock mypool/mydataset
```

#### Use API key from file and read payload from stdin

The `-K` option accepts either a raw API key string or a path to a file containing the key. You can also use `-` to read
the API call payload from stdin (via pipe or input redirection), which is useful for keeping sensitive data out of
command history and process listings.

```bash
# API key from file, payload from stdin via input redirection
midclt -U larry -K /home/larry/truenas_api_key.json call user.create - < /home/larry/user_secret_payload.json

# API key from file, payload from stdin via pipe
cat /path/to/secret/payload.json | midclt -U admin -K /root/.truenas_api_key call user.create -
```

### Scripting

The TrueNAS API client can also be used in Python scripts.

#### Make local API calls

```python
from truenas_api_client import Client

with Client() as c:  # Local IPC
      print(c.ping())  # pong
      user = {"full_name": "John Doe", "username": "user", "password": "pass", "group_create": True}
      entry_id = c.call("user.create", user)
      user = c.call("user.get_instance", entry_id)
      print(user["full_name"])  # John Doe
```

#### Login with a user account or an API key

```python
# User account
with Client(uri="ws://some.other.truenas/api/current") as c:
      c.call("auth.login", username, password)

# API key
with Client(uri="ws://some.other.truenas/api/current") as c:
      c.login_with_api_key(username, key)

# API key file
with Client(uri="ws://some.other.truenas/api/current") as c:
      c.login_with_api_key(username, "/path/to/keyfile.json")
```

### API Key Storage Formats

TrueNAS API keys can be stored in multiple formats. The key material is provided by TrueNAS when generating an
API key. SCRAM-SHA512 authentication is supported in TrueNAS version 26 and later. Earlier versions use plain API key
authentication.

#### Raw API Key

The raw API key string returned by TrueNAS in the `key` field of `api_key.create` response.
Format: `{api_key_id}-{raw_key_material}`

```
1-uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4
```

This can be passed directly to `login_with_api_key()` or stored in a file.

#### JSON Format

Store the raw key:
```json
{
  "raw_key": "1-uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4",
  "api_key_id": 1
}
```

Or store pre-computed keys (TrueNAS 26+):
```json
{
  "client_key": "base64_encoded_client_key",
  "stored_key": "base64_encoded_stored_key",
  "server_key": "base64_encoded_server_key",
  "api_key_id": 1
}
```

Pre-computed keys avoid PBKDF2 computation on the client side.

#### INI Format

Store keys in INI-style configuration files:

```ini
[TRUENAS_API_KEY]
client_key = base64_encoded_client_key
stored_key = base64_encoded_stored_key
server_key = base64_encoded_server_key
api_key_id = 1
```

The `[TRUENAS_API_KEY]` section header is required for INI files with multiple sections.
For single-section files, any section name is accepted. Files without section headers use the DEFAULT section.

#### Start a job

```python
with Client() as c:
      is_locked = c.call("pool.dataset.lock", "mypool/mydataset", job=True)
      if is_locked:
            args = {"datasets": [{"name": "mypool/mydataset", "passphrase": "passphrase"}]}
            c.call("pool.dataset.unlock", "mypool/mydataset", args, job=True)
```

## API Rate Limits

The TrueNAS API enforces strict security checking and auditing in place to detect and prevent brute force or malicious API behavior. 

Connections to the API are currently limited to 20 Auth attempts AND/OR unauthenticated API requests in a 60 second period (subject to future change). Exceeding this limit results in a 10-minute rate limit cooldown before API connections can be re-established. 

Developers are highly recommended to architect their tools in a way that uses a single persistent websocket connection that remains connected for subsequent API calls to be issued without a re-auth.

Developers that need to issue large quantities of subsequent operations (example: massive bulk dataset creations) are highly encouraged to leverage the `core.bulk` endpoint for queuing actions.

## Helpful Links

<a href="https://truenas.com">
<img align="right" src="https://www.truenas.com/docs/images/truenas-logo-mark.png" />
</a>

- [TrueNAS API docs](https://api.truenas.com/)
- [Official TrueNAS Documentation Hub](https://www.truenas.com/docs/)
- [Forums](https://www.truenas.com/community/)
