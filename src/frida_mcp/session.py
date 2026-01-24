"""Session management for Frida connections."""

import time as time_module
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

import frida
import uuid

DEFAULT_API_TIMEOUT = 5


def with_timeout(func, timeout=DEFAULT_API_TIMEOUT):
    """Run a function with a timeout. Raises TimeoutError if exceeded."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout}s")


@dataclass
class FridaSession:
    """Encapsulates all state for a single Frida session."""
    id: str
    device: frida.core.Device
    session: frida.core.Session
    api: Any  # RPC exports
    target: str
    pid: int
    persistent_scripts: list = field(default_factory=list)
    hook_messages: list = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock)

    def add_message(self, hook_name: str, payload: Any, is_error: bool = False):
        """Thread-safe message addition with size limits."""
        with self._lock:
            if is_error:
                self.hook_messages.append({
                    "hook": hook_name,
                    "error": payload,
                    "ts": time_module.time()
                })
            else:
                if isinstance(payload, str) and len(payload) > 10000:
                    payload = payload[:10000] + "...[truncated]"
                self.hook_messages.append({
                    "hook": hook_name,
                    "payload": payload,
                    "ts": time_module.time()
                })
            if len(self.hook_messages) > 100:
                self.hook_messages = self.hook_messages[-100:]

    def get_messages(self, clear: bool = False) -> list:
        """Thread-safe message retrieval."""
        with self._lock:
            messages = list(self.hook_messages[-50:])
            if clear:
                self.hook_messages = []
            return messages

    def clear_messages(self) -> int:
        """Thread-safe message clearing."""
        with self._lock:
            count = len(self.hook_messages)
            self.hook_messages = []
            return count

    def is_alive(self) -> bool:
        """Check if session is still connected."""
        try:
            self.session._impl.pid
            return True
        except Exception:
            return False

    def detach(self):
        """Clean up session resources."""
        for hook in self.persistent_scripts:
            try:
                hook["script"].unload()
            except Exception:
                pass
        self.persistent_scripts = []
        try:
            self.session.detach()
        except Exception:
            pass


class SessionRegistry:
    """Manages multiple Frida sessions with a default active session."""

    def __init__(self):
        self._sessions: dict[str, FridaSession] = {}
        self._active_id: Optional[str] = None
        self._lock = RLock()

    def create(self, device: frida.core.Device, session: frida.core.Session,
               api: Any, target: str, pid: int) -> FridaSession:
        """Create and register a new session, making it active."""
        session_id = str(uuid.uuid4())[:8]
        fs = FridaSession(
            id=session_id,
            device=device,
            session=session,
            api=api,
            target=target,
            pid=pid,
        )
        with self._lock:
            self._sessions[session_id] = fs
            self._active_id = session_id
        return fs

    def get_active(self) -> Optional[FridaSession]:
        """Get the currently active session."""
        with self._lock:
            if self._active_id and self._active_id in self._sessions:
                return self._sessions[self._active_id]
            return None

    def get(self, session_id: str) -> Optional[FridaSession]:
        """Get a specific session by ID."""
        with self._lock:
            return self._sessions.get(session_id)

    def set_active(self, session_id: str) -> bool:
        """Switch the active session."""
        with self._lock:
            if session_id in self._sessions:
                self._active_id = session_id
                return True
            return False

    def remove(self, session_id: str) -> bool:
        """Remove and detach a session."""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].detach()
                del self._sessions[session_id]
                if self._active_id == session_id:
                    self._active_id = next(iter(self._sessions), None)
                return True
            return False

    def list_sessions(self) -> list[dict]:
        """List all sessions with their info."""
        with self._lock:
            return [
                {
                    "id": fs.id,
                    "target": fs.target,
                    "pid": fs.pid,
                    "device": fs.device.name,
                    "active": fs.id == self._active_id,
                    "alive": fs.is_alive(),
                }
                for fs in self._sessions.values()
            ]

    def close_all(self):
        """Close all sessions."""
        with self._lock:
            for fs in self._sessions.values():
                fs.detach()
            self._sessions.clear()
            self._active_id = None


# Global session registry
registry = SessionRegistry()


def get_api():
    """Get the current Frida RPC API or raise error."""
    fs = registry.get_active()
    if fs is None:
        raise RuntimeError("Not connected. Use 'connect' tool first.")
    if not fs.is_alive():
        registry.remove(fs.id)
        raise RuntimeError("Session disconnected unexpectedly. Use 'connect' to reconnect.")
    return fs.api


def get_session() -> FridaSession:
    """Get the current FridaSession or raise error."""
    fs = registry.get_active()
    if fs is None:
        raise RuntimeError("Not connected. Use 'connect' tool first.")
    if not fs.is_alive():
        registry.remove(fs.id)
        raise RuntimeError("Session disconnected unexpectedly. Use 'connect' to reconnect.")
    return fs
