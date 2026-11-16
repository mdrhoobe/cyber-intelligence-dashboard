"""Network target validation for public hosts and HTTP(S) URLs."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit


class TargetValidationError(ValueError):
    pass


def validate_public_target(raw):
    """Reject local and non-public targets before starting a scan."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 2048:
        raise TargetValidationError("A nonempty target under 2048 characters is required")
    raw = raw.strip()
    if any(ord(ch) < 32 for ch in raw):
        raise TargetValidationError("Control characters are not allowed")
    try:
        parts = urlsplit(raw if '://' in raw else 'https://' + raw)
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            raise TargetValidationError("Expected HTTP(S) URL, hostname or IP")
        if parts.username is not None or parts.password is not None:
            raise TargetValidationError("URL credentials are not allowed")
        parts.port
        host = parts.hostname.rstrip('.').lower().encode('idna').decode('ascii')
    except (ValueError, UnicodeError) as exc:
        raise TargetValidationError("Invalid URL or hostname") from exc

    if len(host) > 253 or host in ('localhost',) or host.endswith(('.localhost', '.local', '.internal')):
        raise TargetValidationError("Local hostnames are not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if '.' not in host or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in host.split('.')
        ):
            raise TargetValidationError("Invalid public hostname")
        try:
            resolved = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise TargetValidationError("Cannot resolve hostname") from exc
        addresses = [ipaddress.ip_address(entry[4][0].split('%')[0]) for entry in resolved]
    else:
        addresses = [ip]
    if not addresses or any(not ip.is_global for ip in addresses):
        raise TargetValidationError("Non-public IP addresses are not permitted")
    return host
