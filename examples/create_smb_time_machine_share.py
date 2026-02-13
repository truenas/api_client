from truenas_api_client import Client

DS_NAME = "dozer/test_smb_share"
SHARE_NAME = "SHARE"
API_USERNAME = "api_user"
API_KEY_FILE = "/path/to/api_key.json"  # Can also be a raw key string


with Client("wss://example.internal/api/current") as c:
    # Authenticate using API key (automatically uses SCRAM-SHA512 if available)
    # API_KEY_FILE can be either a file path or the raw key string
    c.login_with_api_key(API_USERNAME, API_KEY_FILE)

    # Check whether we've been configured as an OSX server
    smb_config = c.call("smb.config")
    if not smb_config["aapl_extensions"]:
        c.call("smb.update", {"aapl_extensions": True})

    # Create SMB-style dataset with basic open permissions
    ds = c.call("pool.dataset.create", {"name": DS_NAME, "share_type": "SMB"})

    # Create the actual SMB share for time machine purposes
    c.call("sharing.smb.create", {
        "path": ds["mountpoint"],
        "name": SHARE_NAME,
        "purpose": "TIMEMACHINE"
    })
