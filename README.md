<p align="center">
      <a href="https://discord.gg/Q3St5fPETd"><img alt="Join Discord" src="https://badgen.net/discord/members/Q3St5fPETd/?icon=discord&label=Join%20the%20TrueNAS%20Community" /></a>
 <a href="https://www.truenas.com/community/"><img alt="Join Forums" src="https://badgen.net/badge/Forums/Post%20Now//purple" /></a> 
 <a href="https://jira.ixsystems.com"><img alt="File Issue" src="https://badgen.net/badge/Jira/File%20Issue//red?icon=jira" /></a>
</p>

# TrueNAS Websocket Client

*Found an issue? Please report it on our [Jira bugtracker](https://jira.ixsystems.com).*

## About

The TrueNAS websocket client provides the command line tool `midclt` and the means to easily communicate with [middleware](https://github.com/truenas/middleware) using Python by making calls through the [websocket API](https://www.truenas.com/docs/api/scale_websocket_api.html). The client can connect to a local TrueNAS instance by default or to a specified remote socket. This offers an alternative to going through the [web UI](https://github.com/truenas/webui) or connecting via ssh.

By default, communication facilitated by the API between the client and middleware now uses the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) protocol. However, it is still possible to use the legacy client by passing a legacy uri, e.g. `'ws://some.truenas.address/websocket'` as opposed to `'ws://some.truenas.address/api/current'`.

## API Rate Limits

**NOTE:**

The TrueNAS API enforces strict security checking and auditing in place to detect and prevent brute force or malicious API behaivor. 

Connections to the API are currently limited to 20 Auth attempts AND/OR unauthenticated API requests in a 60 second period (Subject to future change). Exceeding this limit will result in a 10 minute rate limit cooldown before API connections can be re-established. 

Developers are highly recommended to architect their tools in a way that uses a single persistent websocket connection that remains connected for subsequent API calls to be issued without a re-auth.


## Getting Started

TrueNAS comes with this client preinstalled, but it is also possible to use the TrueNAS websocket client from a non-TrueNAS host.

On a non-TrueNAS host, ensure that Git is installed and run `pip install git+https://github.com/truenas/api_client.git` to automatically install dependencies. You may alternatively clone this repository and run `python setup.py install`. Using a Python venv is recommended.

## Usage

The `midclt` command (not to be confused with the [TrueNAS CLI](https://github.com/truenas/midcli)) provides a way to make direct API calls through the client. To view its syntax, enter `midclt -h`. The `-h` option can also be used with any of `midclt`'s subcommands.

The client's default behavior is to connect to the localhost's middlewared socket. For a remote connection, e.g. from a Windows host, you must specify the `--uri` option and authenticate with either user credentials or an API key. For example: `midclt --uri ws://<TRUENAS_IP>/api/current -K key ...`

### Make local API calls

```
root@my_truenas[~]# midclt call user.create '{"full_name": "John Doe", "username": "user", "password": "pass", "group_create": true}'
```

### Login to a remote TrueNAS

```
root@my_truenas[~]# midclt --uri ws://some.other.truenas/api/current -U user -P password call system.info
```

### Start a job

```
root@my_truenas[~]# midclt call -j pool.dataset.lock mypool/mydataset
```

## Development

The TrueNAS API client can also be used in Python scripts.

### Make local API calls

```python
from truenas_api_client import Client

with Client() as c:  # Local IPC
      print(c.ping())  # pong
      user = {"full_name": "John Doe", "username": "user", "password": "pass", "group_create": True}
      entry_id = c.call("user.create", user)
      user = c.call("user.get_instance", entry_id)
      print(user["full_name"])  # John Doe
```

### Login with a user account or an API key

```python
# User account
with Client(uri="ws://some.other.truenas/api/current") as c:
      c.call("auth.login", username, password)

# API key
with Client(uri="ws://some.other.truenas/api/current") as c:
      c.call("auth.login_with_api_key", key)
```

### Start a job

```python
with Client() as c:
      is_locked = c.call("pool.dataset.lock", "mypool/mydataset", job=True)
      if is_locked:
            args = {"datasets": [{"name": "mypool/mydataset", "passphrase": "passphrase"}]}
            c.call("pool.dataset.unlock", "mypool/mydataset", args, job=True)
```

## Helpful Links

<a href="https://truenas.com">
<img align="right" src="https://www.truenas.com/docs/images/TrueNAS_Open_Enterprise_Storage.png" />
</a>

- [Websocket API docs](https://www.truenas.com/docs/api/scale_websocket_api.html)
- [Middleware repo](https://github.com/truenas/middleware)
- [Official TrueNAS Documentation Hub](https://www.truenas.com/docs/)
- [Get started building TrueNAS Scale](https://github.com/truenas/scale-build)
- [Forums](https://www.truenas.com/community/)
