from truenas_api_client import Client

DS_NAME = "dozer/test_smb_share"
SHARE_NAME = "SHARE"
API_USERNAME = "api_user"
API_KEY = "some api key"


with Client("wss://example.internal/api/current") as c:
    # Authenticate using some pre-existing API key
    resp = c.call("auth.login_ex", {
        "mechanism": "API_KEY_PLAIN",
        "username": API_USERNAME,
        "api_key": API_KEY
    })
    assert resp["response_type"] == "SUCCESS"

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
