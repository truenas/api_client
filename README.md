<p align="center">
      <a href="https://discord.gg/Q3St5fPETd"><img alt="Join Discord" src="https://badgen.net/discord/members/Q3St5fPETd/?icon=discord&label=Join%20the%20TrueNAS%20Community" /></a>
 <a href="https://www.truenas.com/community/"><img alt="Join Forums" src="https://badgen.net/badge/Forums/Post%20Now//purple" /></a> 
 <a href="https://jira.ixsystems.com"><img alt="File Issue" src="https://badgen.net/badge/Jira/File%20Issue//red?icon=jira" /></a>
</p>

# TrueNAS Websocket Client

*Found an issue? Please report it on our [Jira bugtracker](https://jira.ixsystems.com).*

## About

The TrueNAS websocket client provides both the command line tool `midclt` and the means for creating a Python script to easily communicate with [middleware](https://github.com/truenas/middleware) by making calls through the [websocket API](https://www.truenas.com/docs/api/scale_websocket_api.html). The client can connect to a local TrueNAS instance by default or to a specified remote socket. This offers an alternative to going through the [web UI](https://github.com/truenas/webui) or connecting via ssh. It also opens up the possibility of automating common tasks.

Communication facilitated by the API between the client and middleware uses the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) protocol.

## Getting Started

TrueNAS comes preinstalled with this client, but it is also possible to use the TrueNAS websocket client from a non-TrueNAS host.

Ensure that Git is installed and run `pip install git+https://github.com/truenas/api_client.git` to automatically install dependencies.

## Usage

### `midclt`

The `midclt` command (not to be confused with the [TrueNAS CLI](https://github.com/truenas/midcli)) provides a direct and interactive way to make API calls through the client. To view its syntax, enter `midclt -h`. The `-h` option can also be used with any of `midclt`'s subcommands.

The primary subcommand of `midclt` is `midclt call`. 

### Instantiating a `Client`



## Development

## Helpful Links

<img align="right" src="https://www.truenas.com/docs/images/TrueNAS_Open_Enterprise_Storage.png" />

- [Websocket API docs](https://www.truenas.com/docs/api/scale_websocket_api.html)
- [Middleware repo](https://github.com/truenas/middleware)
- [Official TrueNAS Documentation Hub](https://www.truenas.com/docs/)
- [Get started building TrueNAS Scale](https://github.com/truenas/scale-build)
- [Forums](https://www.truenas.com/community/)
