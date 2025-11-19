# Copyright (c) 2025 Filippo Lauria <filippo.lauria@iit.cnr.it>

import time
from collections import defaultdict


class RateLimiter:
    """
    Rate limiter to prevent attackers from abusing Cowrie to launch DDoS attacks.

    Prevents abuse where malicious actors attempt to use Cowrie commands
    such as wget, curl, etc. to generate outbound traffic toward victim
    hosts, effectively turning the honeypot into an unwitting participant
    in distributed attacks.

    The limiter tracks outbound requests per destination (hostname/IP) and
    enforces configurable limits to mitigate abuse while still allowing
    malware collection and attacker behavior analysis.
    """

    def __init__(self, enabled: bool = True, max_requests: int = 3,
                 window_seconds: int = 60, max_keys: int = 1000):
        """
        Initialize the rate limiter.

        Args:
            enabled: Whether rate limiting is enabled
            max_requests: Maximum requests per key within the time window
            window_seconds: Time window for rate limiting in seconds
            max_keys: Maximum number of keys to track
        """

        self.enabled = enabled
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.request_tracker: dict[str, list[float]] = defaultdict(list)
        self.last_cleanup = time.time()

    def check(self, key: str) -> bool:
        """
        Check if a request for the given key is allowed.

        Args:
            key: The key to check (e.g., hostname, IP address)

        Returns:
            True if the request is allowed, False if rate limited
        """

        if not self.enabled:
            return True

        current_time = time.time()

        # Periodic global cleanup
        if current_time - self.last_cleanup > self.window_seconds:
            self._cleanup_all(current_time)
            self.last_cleanup = current_time

        # Clean up old requests for this specific key
        self.request_tracker[key] = [
            ts for ts in self.request_tracker[key]
            if current_time - ts < self.window_seconds
        ]

        # Check dictionary size limit
        if len(self.request_tracker) > self.max_keys:
            self._remove_oldest_keys()

        # Check rate limit
        if len(self.request_tracker[key]) >= self.max_requests:
            return False

        # Record this request
        self.request_tracker[key].append(current_time)
        return True

    def _cleanup_all(self, current_time: float) -> None:
        """
        Remove expired entries from all keys.
        """

        empty_keys = []
        for key, timestamps in self.request_tracker.items():
            # Keep only timestamps within the window
            self.request_tracker[key] = [
                ts for ts in timestamps
                if current_time - ts < self.window_seconds
            ]
            # Mark empty keys for removal
            if not self.request_tracker[key]:
                empty_keys.append(key)

        # Remove keys with no recent activity
        for key in empty_keys:
            del self.request_tracker[key]

    def _remove_oldest_keys(self) -> None:
        """
        Remove keys with the oldest activity when tracker gets too large.
        """

        if not self.request_tracker:
            return

        # Find the most recent activity for each key
        key_latest_activity = {}
        for key, timestamps in self.request_tracker.items():
            key_latest_activity[key] = 0 if not timestamps else max(timestamps)

        # Sort by activity time and remove the oldest 10%
        sorted_keys = sorted(key_latest_activity.items(), key=lambda x: x[1])
        keys_to_remove = max(1, len(sorted_keys) // 10)

        for key, _ in sorted_keys[:keys_to_remove]:
            del self.request_tracker[key]

    def reset(self) -> None:
        """
        Clear all tracked requests.
        """

        self.request_tracker.clear()
        self.last_cleanup = time.time()
