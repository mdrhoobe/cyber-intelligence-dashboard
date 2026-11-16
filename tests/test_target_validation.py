"""Offline tests for target filtering."""

import socket
from unittest.mock import patch

import pytest

from target_validation import validate_public_target, TargetValidationError


def dns_public(*args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]


@patch('target_validation.socket.getaddrinfo', side_effect=dns_public)
def test_public_domain(_):
    assert validate_public_target('https://example.com/path') == 'example.com'


@pytest.mark.parametrize('target', [
    '127.0.0.1', '192.168.1.10', '10.1.1.1',
    '169.254.169.254', 'localhost', 'server.local',
    'http://[::1]/', 'file:///etc/passwd', '',
    'http://user:pass@example.com', 'bad host'
])
def test_block_private_or_invalid(target):
    with pytest.raises(TargetValidationError):
        validate_public_target(target)


@patch('target_validation.socket.getaddrinfo')
def test_reject_mixed_dns(mock_dns):
    mock_dns.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.2', 0))
    ]
    with pytest.raises(TargetValidationError):
        validate_public_target('example.com')
