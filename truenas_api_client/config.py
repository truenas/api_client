import os

CALL_TIMEOUT = int(os.environ.get("CALL_TIMEOUT", 60))
"""Default number of seconds to allow an API call until timing out."""

UNCLAIMED_JOBS_MAX = 64
"""Number of legacy server jobs to keep state for before the call result containing the job ID arrives."""
