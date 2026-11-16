"""Isolate test credentials from the developer's runtime environment.

Pytest loads conftest.py before importing test modules that load app.py.
These fixture values exist only in the pytest process.
"""

import os

os.environ.update({
    "CID_PASSWORD": "test-password-for-ci",
    "CID_API_KEY": "test-api-key-for-ci",
    "CID_SECRET_KEY": "test-session-secret-for-ci",
})
