from truenas_api_client import Client


with Client() as client:
    job = client.call("core.ping", job="RETURN")