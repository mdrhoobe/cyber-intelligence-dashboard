"""Authentication and session regressions for local usage."""

import os
os.environ.setdefault("CID_PASSWORD", "test-password-for-ci")
os.environ.setdefault("CID_SECRET_KEY", "test-session-secret-for-ci")

from auth_controls import LoginThrottle
from app import app, login_throttle


def test_throttle_expires_and_is_per_peer():
    now = [0.0]
    limiter = LoginThrottle(max_attempts=2, window_seconds=30, clock=lambda: now[0])
    assert limiter.allowed("peer-a")
    limiter.register_failure("peer-a")
    assert limiter.allowed("peer-a")
    limiter.register_failure("peer-a")
    assert not limiter.allowed("peer-a")
    assert limiter.allowed("peer-b")
    now[0] = 30.0
    assert limiter.allowed("peer-a")


def test_post_logout_needs_csrf_and_clears_session():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["_csrf_token"] = "csrf-test"
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    response = client.post("/logout", data={"csrf_token": "csrf-test"})
    assert response.status_code == 302
    assert client.get("/").status_code == 302


def test_security_headers_present_on_html_and_api():
    client = app.test_client()
    for path in ("/login", "/api/v1"):
        response = client.get(path)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Cache-Control"] == "no-store"


def test_login_rate_limit_resists_repeated_wrong_passwords(monkeypatch):
    client = app.test_client()
    peer = "198.51.100.77"
    login_throttle.reset(peer)
    assert client.get("/login").status_code == 200
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    for _ in range(5):
        response = client.post("/login", data={
            "password": "wrong", "csrf_token": token,
        }, environ_overrides={"REMOTE_ADDR": peer})
        assert response.status_code == 200
    response = client.post("/login", data={
        "password": "test-password-for-ci", "csrf_token": token,
    }, environ_overrides={"REMOTE_ADDR": peer})
    assert response.status_code == 429
    login_throttle.reset(peer)
