"""Local application smoke tests; no external requests are made."""

import os

os.environ.setdefault('CID_PASSWORD', 'test-password-for-ci')
os.environ.setdefault('CID_API_KEY', 'test-api-key-for-ci')
os.environ.setdefault('CID_SECRET_KEY', 'test-session-secret-for-ci')

from app import app


def test_login_and_authenticated_dashboard():
    app.testing = True
    client = app.test_client()
    login_page = client.get('/login')
    assert login_page.status_code == 200
    with client.session_transaction() as sess:
        token = sess['_csrf_token']
    response = client.post('/login', data={
        'password': 'test-password-for-ci',
        'csrf_token': token,
    })
    assert response.status_code == 302
    assert client.get('/').status_code == 200


def test_form_requires_csrf_token():
    client = app.test_client()
    response = client.post('/login', data={'password': 'test-password-for-ci'})
    assert response.status_code == 400


def test_api_requires_secret_header():
    client = app.test_client()
    assert client.post('/api/v1/domain', json={'domain': 'example.com'}).status_code == 401


def test_api_rejects_private_address_before_scan():
    client = app.test_client()
    response = client.post(
        '/api/v1/domain', json={'domain': '127.0.0.1'},
        headers={'X-API-Key': 'test-api-key-for-ci'},
    )
    assert response.status_code == 400
