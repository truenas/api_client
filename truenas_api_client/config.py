import os

CALL_TIMEOUT = int(os.environ.get("CALL_TIMEOUT", 60))
"""Default number of seconds to allow an API call until timing out."""
