# Security notes

This repository is an educational prototype. It is not hardened for exposure to anonymous users on the public internet.

## Required before further publication

1. Rotate the passwords and API key that previously appeared in tracked source files. Deleting current file contents does **not** remove old credentials from Git history.
2. Inspect the previously committed SQLite database and JSON backup for personal or sensitive records. They have been removed from the current branch, but may remain available through earlier commits, forks, or caches.
3. If those records are sensitive, consider making the repository private while planning a history rewrite with proper authorization. History rewriting does not revoke data already downloaded by others.
4. Keep `CID_HOST=127.0.0.1` and `debug=False` for local use. External hosting needs HTTPS, separate auth, rate limiting, secret management, and a dedicated security review.
5. Only scan systems with explicit permission. Never use production personal identifiers as sample data.

The target validator blocks non-global addresses after DNS lookup, and redirects are not followed in core scan requests. It is a defense-in-depth measure, **not** a full protection against DNS rebinding or other network-layer attacks.

## Additional controls

A local login throttle limits repeated guesses per source address, protected forms use session tokens, and responses disable caching and framing. These controls do not replace reverse-proxy enforcement or platform-level protection for an externally accessible service. The scheduler is deliberately not started by importing the web application.
