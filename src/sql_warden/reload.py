"""Reloading the policy while a server runs, on SIGHUP.

The new policy is built in full before anything changes: the file read and validated, every
profile's Warden made and its role looked at, as at startup. Only then is it swapped in, in
one step. If any of that fails, nothing changes: the server keeps answering with the policy
it had, and says why in its log. Requests already being answered finish with the policy
they started with.
"""

import logging
import signal
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sql_warden.metrics import Metrics
from sql_warden.server import LivePolicy, Policy

log = logging.getLogger("sql_warden.reload")

SETTLE_S = 5.0
"""How long a replaced Warden is left alone before it is closed: a request that read the
old policy just before the swap may not have reached it yet."""
RETIRE_AFTER_S = 120.0
"""How long a replaced Warden's requests may take to finish before it is closed anyway.
Anything that still needs it opens what it uses again."""


class ReloadError(Exception):
    """Why a policy couldn't be loaded, written to be shown: it holds no secrets."""


class Reloader:
    """Builds a new policy on request and swaps it in whole, or not at all.

    build is given the policy being served and returns the one to serve instead, raising
    ReloadError (or anything else, for a bug) if it can't."""

    def __init__(
        self,
        live: LivePolicy,
        build: Callable[[Policy], Policy],
        *,
        source: str = "the policy file",
        metrics: Metrics | None = None,
        settle_s: float = SETTLE_S,
        retire_after_s: float = RETIRE_AFTER_S,
    ) -> None:
        self.live = live
        self._build = build
        self._source = source
        self._metrics = metrics
        self._settle_s = settle_s
        self._retire_after_s = retire_after_s
        self._lock = threading.Lock()
        self._running = False
        self._again = False
        self._retiring: list[threading.Thread] = []

    def reload(self) -> bool:
        """Build the policy afresh and serve it. True if it is served now; False if the old
        one still is, with the reason logged."""
        current = self.live.current
        try:
            new = self._build(current)
        except Exception as exc:
            return self._failed(_reason(exc))
        try:
            old = self.live.swap(new)
        except ValueError as exc:
            _close(new)
            return self._failed(str(exc))
        profiles = ", ".join(warden.profile for warden in new.all)
        noun = "profile" if len(new.all) == 1 else "profiles"
        log.info("reloaded %s: serving %s %s", self._source, noun, profiles)
        if self._metrics is not None:
            self._metrics.reloads.inc(outcome="applied")
            self._metrics.last_reload_ok.set(1)
        self._retire(old)
        return True

    def request(self) -> None:
        """Reload in the background: what a signal handler calls. One reload runs at a
        time; asked again while one runs, one more follows it, so the file as it is after
        the last signal is the one loaded."""
        with self._lock:
            if self._running:
                self._again = True
                return
            self._running = True
        threading.Thread(target=self._reload_until_asked_no_more, daemon=True).start()

    @contextmanager
    def on_sighup(self) -> Iterator[bool]:
        """Reload on SIGHUP while inside; whether it does (not where the platform has no
        SIGHUP, nor outside the main thread, where Python can't take signals). The handler
        there before is put back after."""
        hangup = getattr(signal, "SIGHUP", None)
        if hangup is None or threading.current_thread() is not threading.main_thread():
            yield False
            return
        before = signal.signal(hangup, lambda signum, frame: self.request())
        try:
            yield True
        finally:
            signal.signal(hangup, before)

    def wait(self, timeout_s: float = 30.0) -> None:
        """Until no reload is running and replaced Wardens are closed. For tests."""
        deadline = time.monotonic() + timeout_s
        while True:
            with self._lock:
                running = self._running
            if not running and not any(thread.is_alive() for thread in self._retiring):
                return
            if time.monotonic() > deadline:
                raise TimeoutError("the reload did not finish")
            time.sleep(0.01)

    def _reload_until_asked_no_more(self) -> None:
        while True:
            try:
                self.reload()
            except Exception as exc:  # the server goes on either way
                self._failed(_reason(exc))
            with self._lock:
                if not self._again:
                    self._running = False
                    return
                self._again = False

    def _failed(self, reason: str) -> bool:
        log.error(
            "could not reload %s, so the policy loaded before is still served: %s",
            self._source,
            reason,
        )
        if self._metrics is not None:
            self._metrics.reloads.inc(outcome="failed")
            self._metrics.last_reload_ok.set(0)
        return False

    def _retire(self, old: Policy) -> None:
        """Close the replaced Wardens once their requests are done."""

        def retire() -> None:
            time.sleep(self._settle_s)
            deadline = time.monotonic() + self._retire_after_s
            while not all(warden.idle for warden in old.all) and time.monotonic() < deadline:
                time.sleep(0.1)
            _close(old)

        thread = threading.Thread(target=retire, daemon=True)
        self._retiring = [t for t in self._retiring if t.is_alive()] + [thread]
        thread.start()


def _close(policy: Policy) -> None:
    for warden in policy.all:
        try:
            warden.close()
        except Exception as exc:  # nothing is left that needs it
            log.warning("closing profile %s's connections: %s", warden.profile, _reason(exc))


def _reason(exc: Exception) -> str:
    # A ReloadError is written to be shown; anything else is a bug, named but not shown,
    # since its message could hold anything, a connection string included.
    if isinstance(exc, ReloadError):
        return str(exc)
    return f"unexpected {type(exc).__name__}"
