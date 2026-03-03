"""Cross-process priority lock for the local LLM (Ollama).

Ollama can only serve one request at a time.  When the hunting pipeline
and the analyst chat both need the LLM, hunts must take priority.

This module provides a simple file-lock mechanism:

* **HUNT** callers acquire the lock immediately and set a ``hunt``
  marker.  If a CHAT call is in-flight they wait for it to finish
  (short — analyst queries are lighter) then proceed.
* **CHAT** callers check for an active hunt marker.  If one exists
  they poll until it clears (up to *timeout* seconds) before
  proceeding.  This means chat queries naturally slot into the gaps
  between hunt LLM calls.

The lock file lives at ``data/.llm_priority_lock`` and uses ``fcntl``
advisory file locking so it works across the subprocess boundary.
"""

import fcntl
import json
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger("artemis.llm.priority")

_LOCK_DIR = Path("data")
_LOCK_FILE = _LOCK_DIR / ".llm_priority_lock"
_STATE_FILE = _LOCK_DIR / ".llm_priority_state"

# How often CHAT callers poll while waiting for a hunt to finish.
_POLL_INTERVAL = 0.5  # seconds


def _ensure_dir():
    _LOCK_DIR.mkdir(parents=True, exist_ok=True)


def _read_state() -> dict:
    """Read the current priority state (non-locking)."""
    try:
        if _STATE_FILE.exists():
            raw = _STATE_FILE.read_text().strip()
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    return {}


def _write_state(state: dict):
    """Write priority state atomically."""
    try:
        _ensure_dir()
        tmp = _STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(_STATE_FILE)
    except Exception:
        pass


def _clear_state():
    """Remove the state file."""
    try:
        _STATE_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _is_stale(state: dict, max_age: float = 120.0) -> bool:
    """Return True if the state timestamp is older than *max_age* seconds."""
    ts = state.get("ts", 0)
    return (time.time() - ts) > max_age


@contextmanager
def llm_priority_hunt():
    """Context manager for hunt-priority LLM access.

    Acquires an exclusive file lock, marks the LLM as hunt-active,
    and releases when the call is done.
    """
    _ensure_dir()
    fd = None
    try:
        fd = os.open(str(_LOCK_FILE), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)  # block until available
        _write_state({"holder": "hunt", "ts": time.time(), "pid": os.getpid()})
        yield
    finally:
        _clear_state()
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except Exception:
                pass


@contextmanager
def llm_priority_chat(timeout: float = 90.0):
    """Context manager for chat-priority (low) LLM access.

    Waits for any active hunt LLM call to finish before acquiring.
    If the wait exceeds *timeout* seconds, raises ``LLMBusyError``.
    """
    _ensure_dir()
    deadline = time.time() + timeout

    # Phase 1: wait for any hunt holder to release
    while True:
        state = _read_state()
        if not state or state.get("holder") != "hunt" or _is_stale(state):
            break
        if time.time() >= deadline:
            raise LLMBusyError(
                "Threat hunting is actively using the LLM. "
                "Your query will be processed when the current hunt "
                "analysis step completes."
            )
        time.sleep(_POLL_INTERVAL)

    # Phase 2: acquire the lock
    fd = None
    try:
        fd = os.open(str(_LOCK_FILE), os.O_CREAT | os.O_RDWR)
        # Use non-blocking first — if a hunt just grabbed it, fall back
        # to blocking with the remaining timeout.
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            # Hunt grabbed it between our state-check and lock attempt.
            # Wait with remaining time.
            remaining = deadline - time.time()
            if remaining <= 0:
                raise LLMBusyError(
                    "Threat hunting is actively using the LLM. "
                    "Try again in a moment."
                )
            # Block until the hunt releases (should be fast per-call)
            fcntl.flock(fd, fcntl.LOCK_EX)

        _write_state({"holder": "chat", "ts": time.time(), "pid": os.getpid()})
        yield
    finally:
        _clear_state()
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except Exception:
                pass


class LLMBusyError(Exception):
    """Raised when the LLM is busy with higher-priority work."""
    pass
