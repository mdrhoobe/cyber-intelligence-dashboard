"""In-process throttling for the single-user local dashboard."""

import time
from threading import Lock


class LoginThrottle:
    def __init__(self, max_attempts=5, window_seconds=300, clock=None):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.clock = clock or time.monotonic
        self._failures = {}
        self._lock = Lock()

    def allowed(self, peer):
        now = self.clock()
        with self._lock:
            recent = [
                t for t in self._failures.get(peer, [])
                if now - t < self.window_seconds
            ]
            if recent:
                self._failures[peer] = recent
            else:
                self._failures.pop(peer, None)
            return len(recent) < self.max_attempts

    def register_failure(self, peer):
        now = self.clock()
        with self._lock:
            recent = [
                t for t in self._failures.get(peer, [])
                if now - t < self.window_seconds
            ]
            recent.append(now)
            self._failures[peer] = recent
            if len(self._failures) > 2048:
                self._failures = {k: v for k, v in self._failures.items()
                                  if v and now - v[-1] < self.window_seconds}

    def reset(self, peer):
        with self._lock:
            self._failures.pop(peer, None)
