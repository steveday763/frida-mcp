#!/usr/bin/env python3
"""
Frida MCP Server - Mobile security testing via Model Context Protocol

Exposes Frida functionality as MCP tools for AI-assisted security research.
"""

import json
import asyncio
import subprocess
import time as time_module
from typing import Any
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

import frida
from dataclasses import dataclass, field
from threading import Event, Lock, RLock
from typing import Optional
import uuid

# Default timeout for API calls (seconds)
DEFAULT_API_TIMEOUT = 5

def _with_timeout(func, timeout=DEFAULT_API_TIMEOUT):
    """Run a function with a timeout. Raises TimeoutError if exceeded."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout}s")

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


# ============================================================================
# SESSION MANAGEMENT (multi-device capable)
# ============================================================================

@dataclass
class FridaSession:
    """Encapsulates all state for a single Frida session"""
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
        """Thread-safe message addition with size limits"""
        with self._lock:
            if is_error:
                self.hook_messages.append({
                    "hook": hook_name,
                    "error": payload,
                    "ts": time_module.time()
                })
            else:
                # Truncate large payloads
                if isinstance(payload, str) and len(payload) > 10000:
                    payload = payload[:10000] + "...[truncated]"
                self.hook_messages.append({
                    "hook": hook_name,
                    "payload": payload,
                    "ts": time_module.time()
                })
            # Cap at 100 messages
            if len(self.hook_messages) > 100:
                self.hook_messages = self.hook_messages[-100:]

    def get_messages(self, clear: bool = False) -> list:
        """Thread-safe message retrieval"""
        with self._lock:
            messages = list(self.hook_messages[-50:])
            if clear:
                self.hook_messages = []
            return messages

    def clear_messages(self) -> int:
        """Thread-safe message clearing"""
        with self._lock:
            count = len(self.hook_messages)
            self.hook_messages = []
            return count

    def is_alive(self) -> bool:
        """Check if session is still connected"""
        try:
            self.session._impl.pid
            return True
        except Exception:
            return False

    def detach(self):
        """Clean up session resources"""
        # Unload persistent scripts
        for hook in self.persistent_scripts:
            try:
                hook["script"].unload()
            except Exception:
                pass
        self.persistent_scripts = []

        # Detach session
        try:
            self.session.detach()
        except Exception:
            pass


class SessionRegistry:
    """
    Manages multiple Frida sessions with a default "active" session.

    For backwards compatibility, most operations use the active session.
    Future: Allow explicit session_id parameters for multi-device work.
    """
    def __init__(self):
        self._sessions: dict[str, FridaSession] = {}
        self._active_id: Optional[str] = None
        self._lock = RLock()

    def create(self, device: frida.core.Device, session: frida.core.Session,
               api: Any, target: str, pid: int) -> FridaSession:
        """Create and register a new session, making it active"""
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
        """Get the currently active session"""
        with self._lock:
            if self._active_id and self._active_id in self._sessions:
                return self._sessions[self._active_id]
            return None

    def get(self, session_id: str) -> Optional[FridaSession]:
        """Get a specific session by ID"""
        with self._lock:
            return self._sessions.get(session_id)

    def set_active(self, session_id: str) -> bool:
        """Switch the active session"""
        with self._lock:
            if session_id in self._sessions:
                self._active_id = session_id
                return True
            return False

    def remove(self, session_id: str) -> bool:
        """Remove and detach a session"""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].detach()
                del self._sessions[session_id]
                if self._active_id == session_id:
                    # Switch to another session if available
                    self._active_id = next(iter(self._sessions), None)
                return True
            return False

    def remove_active(self) -> bool:
        """Remove the active session"""
        with self._lock:
            if self._active_id:
                return self.remove(self._active_id)
            return False

    def list_sessions(self) -> list[dict]:
        """List all sessions with their info"""
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
        """Close all sessions"""
        with self._lock:
            for fs in self._sessions.values():
                fs.detach()
            self._sessions.clear()
            self._active_id = None


# Global session registry (replaces individual globals)
_registry = SessionRegistry()


def get_api():
    """Get the current Frida RPC API or raise error"""
    fs = _registry.get_active()
    if fs is None:
        raise RuntimeError("Not connected. Use 'connect' tool first.")

    if not fs.is_alive():
        _registry.remove(fs.id)
        raise RuntimeError("Session disconnected unexpectedly. Use 'connect' to reconnect.")

    return fs.api


def get_session() -> FridaSession:
    """Get the current FridaSession or raise error"""
    fs = _registry.get_active()
    if fs is None:
        raise RuntimeError("Not connected. Use 'connect' tool first.")

    if not fs.is_alive():
        _registry.remove(fs.id)
        raise RuntimeError("Session disconnected unexpectedly. Use 'connect' to reconnect.")

    return fs


def is_connected() -> dict:
    """Check if Frida session is still alive and healthy"""
    fs = _registry.get_active()
    if fs is None:
        return {"connected": False, "reason": "no_session"}

    try:
        pid = fs.session._impl.pid
        # Quick RPC check
        modules = fs.api.memory_list_modules()
        module_count = len(modules) if modules else 0
        return {
            "connected": True,
            "session_id": fs.id,
            "pid": pid,
            "device": fs.device.name,
            "module_count": module_count,
        }
    except Exception as e:
        return {"connected": False, "reason": str(e)}


# ============================================================================
# DEVICE & CONNECTION MANAGEMENT
# ============================================================================

def list_devices() -> list[dict]:
    """List all available Frida devices"""
    devices = []
    for device in frida.enumerate_devices():
        devices.append({
            "id": device.id,
            "name": device.name,
            "type": device.type,
        })
    return devices


def list_processes(device_id: str | None = None) -> list[dict]:
    """List processes on a device"""
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=5)

    processes = []
    for proc in device.enumerate_processes():
        processes.append({
            "pid": proc.pid,
            "name": proc.name,
        })
    return processes


def list_apps(device_id: str | None = None) -> list[dict]:
    """List installed applications on a device"""
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=5)

    apps = []
    for app in device.enumerate_applications():
        apps.append({
            "identifier": app.identifier,
            "name": app.name,
            "pid": app.pid if app.pid else None,
        })
    return apps


def _run_script_sync(js_code: str, timeout_ms: int = 5000) -> dict:
    """
    Run a Frida script and wait for it to send a result.
    Uses threading.Event for efficient waiting instead of polling.
    The script should send() its result - we return the first message received.
    """
    fs = get_session()

    script = fs.session.create_script(js_code)
    result = {"payload": None, "error": None}
    done_event = Event()

    def on_msg(msg, data):
        if msg["type"] == "send":
            result["payload"] = msg["payload"]
            done_event.set()
        elif msg["type"] == "error":
            result["error"] = msg.get("stack", str(msg))
            done_event.set()

    script.on("message", on_msg)
    script.load()

    # Wait for result with timeout (Event-based, no polling)
    completed = done_event.wait(timeout=timeout_ms / 1000.0)

    try:
        script.unload()
    except Exception:
        pass

    if not completed:
        raise TimeoutError(f"Script execution timed out after {timeout_ms}ms")

    if result["error"]:
        raise RuntimeError(result["error"])
    return result["payload"]


def _wait_for_pid(package: str, device_id: str | None, timeout_ms: int = 10000) -> int:
    """Poll for PID to appear after launching app"""
    start = time_module.time()
    while (time_module.time() - start) * 1000 < timeout_ms:
        pid_output = _adb_shell(["pidof", package], device_id)
        if pid_output:
            return int(pid_output.split()[0])
        time_module.sleep(0.2)
    raise RuntimeError(f"Timeout waiting for {package} to start")


def connect(
    target: str,
    device_id: str | None = None,
    spawn: bool = False,
    timeout_ms: int = 15000,
) -> dict:
    """Connect to an app by name/bundle ID or PID"""
    global _registry

    # Disconnect existing active session (backwards compatible behavior)
    active = _registry.get_active()
    if active:
        _registry.remove(active.id)

    # Get device
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=10)

    # Ensure SELinux is permissive (required for Frida agent injection)
    selinux_status = _ensure_selinux_permissive(device_id)

    # Determine if target is PID or name
    pid = None
    spawn_method = None
    try:
        pid = int(target)
        frida_session = device.attach(pid)
        target_name = target
    except ValueError:
        # It's a name/bundle ID (package name)
        if spawn:
            # Use reliable adb-based spawn instead of Frida's spawn (which often times out)
            # 1. Force stop the app
            _adb_shell(["am", "force-stop", target], device_id)

            # 2. Wait for process to actually die (poll up to 2s)
            for _ in range(10):
                time_module.sleep(0.2)
                if not _adb_shell(["pidof", target], device_id):
                    break

            # 3. Small extra delay for system cleanup
            time_module.sleep(0.3)

            # 4. Launch via monkey (finds launcher activity automatically)
            _adb_shell([
                "monkey", "-p", target,
                "-c", "android.intent.category.LAUNCHER", "1"
            ], device_id)

            # 5. Smart wait: poll for PID to appear
            pid = _wait_for_pid(target, device_id, timeout_ms)

            # 6. Attach to PID
            frida_session = device.attach(pid)

            spawn_method = "adb_launch"
        else:
            frida_session = device.attach(target)
        target_name = target

    # Load the objection agent script
    agent_source = _get_agent_source()
    script = frida_session.create_script(agent_source)

    # Get actual PID before creating FridaSession
    actual_pid = pid
    if actual_pid is None:
        try:
            actual_pid = frida_session._impl.pid
        except Exception:
            actual_pid = 0

    # Create a placeholder session to capture messages during load
    # We'll update the api after script loads
    script.load()
    api = script.exports_sync

    # Create and register the session
    fs = _registry.create(
        device=device,
        session=frida_session,
        api=api,
        target=target_name,
        pid=actual_pid,
    )

    # Set up message handler that routes to our session
    def on_message(message, data):
        import sys
        if message["type"] == "send":
            payload = message['payload']
            # Truncate long payloads for console
            display = str(payload)[:200] + '...' if len(str(payload)) > 200 else str(payload)
            print(f"[FRIDA] {display}", file=sys.stderr)
            # Capture all bracketed messages to retrievable queue
            if isinstance(payload, str) and payload.startswith('['):
                fs.add_message("agent", payload)
        elif message["type"] == "error":
            print(f"[ERROR] {message.get('stack', message)}", file=sys.stderr)

    script.on("message", on_message)

    result = {
        "status": "connected",
        "session_id": fs.id,
        "device": device.name,
        "target": target_name,
        "pid": actual_pid,
        "selinux": selinux_status,
    }
    if spawn_method:
        result["spawn_method"] = spawn_method
    return result


def disconnect() -> dict:
    """Disconnect from current session"""
    global _registry

    active = _registry.get_active()
    if active:
        session_id = active.id
        _registry.remove(session_id)
        return {"status": "disconnected", "session_id": session_id}

    return {"status": "not_connected"}


def list_sessions() -> list[dict]:
    """List all active Frida sessions"""
    global _registry
    return _registry.list_sessions()


def switch_session(session_id: str) -> dict:
    """Switch to a different active session by ID"""
    global _registry
    if _registry.set_active(session_id):
        fs = _registry.get(session_id)
        return {
            "status": "switched",
            "session_id": session_id,
            "target": fs.target if fs else None,
            "pid": fs.pid if fs else None,
        }
    return {"status": "error", "message": f"Session {session_id} not found"}


# ============================================================================
# ADB HELPERS (for spawn/launch workflow)
# ============================================================================

def _adb_shell(cmd: list[str], device_id: str | None = None) -> str:
    """Run adb shell command and return output"""
    args = ["adb"]
    if device_id:
        args.extend(["-s", device_id])
    args.extend(["shell"] + cmd)
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip()


def _ensure_selinux_permissive(device_id: str | None = None) -> str:
    """Set SELinux to permissive mode (required for Frida on some devices)"""
    # Check current mode
    current = _adb_shell(["su", "-c", "getenforce"], device_id)
    if current.lower() == "permissive":
        return "already_permissive"
    # Set to permissive
    _adb_shell(["su", "-c", "setenforce 0"], device_id)
    # Verify
    new_mode = _adb_shell(["su", "-c", "getenforce"], device_id)
    return f"set_to_{new_mode.lower()}"


def _adb_cmd(cmd: list[str], device_id: str | None = None) -> str:
    """Run adb command (not shell) and return output"""
    args = ["adb"]
    if device_id:
        args.extend(["-s", device_id])
    args.extend(cmd)
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip()


def get_pid(package: str, device_id: str | None = None) -> dict:
    """Get PID of running app by package name"""
    output = _adb_shell(["pidof", package], device_id)
    if output:
        # pidof can return multiple PIDs, take the first one
        pid_str = output.split()[0]
        try:
            return {"package": package, "pid": int(pid_str)}
        except ValueError:
            return {"package": package, "pid": None, "error": f"Invalid PID: {pid_str}"}
    return {"package": package, "pid": None}


def launch_app(
    package: str,
    activity: str | None = None,
    device_id: str | None = None,
    timeout_ms: int = 10000,
) -> dict:
    """Launch app via adb and return its PID (smart wait for process)"""
    if activity:
        # Launch specific activity
        component = f"{package}/{activity}" if not activity.startswith(package) else activity
        output = _adb_shell(["am", "start", "-n", component], device_id)
    else:
        # Launch via monkey (finds launcher activity automatically)
        output = _adb_shell([
            "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1"
        ], device_id)

    # Smart wait: poll for PID to appear
    try:
        pid = _wait_for_pid(package, device_id, timeout_ms)
    except RuntimeError:
        pid = None

    return {
        "package": package,
        "activity": activity,
        "pid": pid,
        "output": output,
    }


def stop_app(package: str, device_id: str | None = None) -> dict:
    """Force stop an app"""
    output = _adb_shell(["am", "force-stop", package], device_id)
    return {"package": package, "stopped": True, "output": output}


def spawn_and_attach(
    package: str,
    device_id: str | None = None,
    wait_ms: int = 5000,
) -> dict:
    """
    Force stop app, launch fresh, and attach Frida.
    This is a convenience wrapper around connect(spawn=True).
    """
    # connect(spawn=True) now uses the reliable adb-based approach
    return connect(package, device_id, spawn=True, timeout_ms=wait_ms)


# ============================================================================
# MEMORY OPERATIONS
# ============================================================================

def memory_list_modules() -> list[dict]:
    """List loaded modules in the process"""
    api = get_api()
    return _with_timeout(lambda: api.memory_list_modules())


def memory_list_exports(module_name: str) -> list[dict]:
    """List exports from a module"""
    api = get_api()
    return _with_timeout(lambda: api.memory_list_exports(module_name))


def memory_search(pattern: str, is_string: bool = False) -> list[dict]:
    """Search memory for a pattern (hex bytes or string)"""
    api = get_api()
    return _with_timeout(lambda: api.memory_search(pattern, is_string), timeout=10)


def memory_read(address: str, size: int) -> str:
    """Read memory at address, return as hex string"""
    api = get_api()
    return _with_timeout(lambda: api.memory_read(address, size))


# ============================================================================
# ANDROID HOOKING
# ============================================================================

def android_list_classes(pattern: str | None = None) -> list[str]:
    """List loaded Java classes, optionally filtered by pattern"""
    api = get_api()
    classes = _with_timeout(lambda: api.android_hooking_get_classes(), timeout=10)
    if pattern:
        pattern_lower = pattern.lower()
        classes = [c for c in classes if pattern_lower in c.lower()]
    return classes[:500]  # Limit output


def android_list_methods(class_name: str) -> list[str]:
    """List methods of a Java class"""
    api = get_api()
    return _with_timeout(lambda: api.android_hooking_get_class_methods(class_name))


def android_hook_method(
    class_name: str,
    method_name: str,
    dump_args: bool = True,
    dump_return: bool = True,
    dump_backtrace: bool = False,
) -> dict:
    """Hook a Java method to monitor calls"""
    api = get_api()
    target = f"{class_name}!{method_name}"
    api.android_hooking_watch(target, dump_args, dump_backtrace, dump_return)
    return {"status": "hooked", "target": target}


def android_search_classes(pattern: str) -> list[dict]:
    """Search for classes matching pattern"""
    api = get_api()
    return _with_timeout(lambda: api.android_hooking_enumerate(pattern), timeout=10)


def android_ssl_pinning_disable() -> dict:
    """Disable SSL certificate pinning"""
    api = get_api()
    api.android_sslpinning_disable()
    return {"status": "ssl_pinning_disabled"}


def android_get_current_activity() -> str:
    """Get the current foreground activity"""
    api = get_api()
    return _with_timeout(lambda: api.android_hooking_get_current_activity())


# ============================================================================
# FILE OPERATIONS
# ============================================================================

def file_ls(path: str = ".") -> list[dict]:
    """List files in directory"""
    api = get_api()
    return _with_timeout(lambda: api.file_ls(path))


def file_read(path: str) -> str:
    """Read a file from the device"""
    api = get_api()
    return _with_timeout(lambda: api.file_read(path))


def file_download(remote_path: str, local_path: str) -> dict:
    """Download a file from device to local machine"""
    api = get_api()
    data = _with_timeout(lambda: api.file_download(remote_path), timeout=30)
    with open(local_path, 'wb') as f:
        f.write(bytes(data))
    return {"status": "downloaded", "path": local_path, "size": len(data)}


def run_java(code: str) -> Any:
    """Run arbitrary Java code within Java.performNow context. Has access to Java.use(), Java.choose(), etc."""
    api = get_api()
    return _with_timeout(lambda: api.run_java(code), timeout=10)


# ============================================================================
# CUSTOM SCRIPTING
# ============================================================================

def run_script(js_code: str, timeout_ms: int = 2000) -> Any:
    """Execute custom Frida JavaScript code and collect messages.
    Uses Event-based idle detection for efficient waiting.
    """
    fs = get_session()

    script = fs.session.create_script(js_code)
    result = {"messages": []}
    message_event = Event()
    error_event = Event()
    lock = Lock()

    def on_message(message, data):
        with lock:
            if message["type"] == "send":
                result["messages"].append(message["payload"])
                message_event.set()
            elif message["type"] == "error":
                result["error"] = message["stack"]
                error_event.set()

    script.on("message", on_message)
    script.load()

    # Wait for messages with timeout
    # Strategy: wait for first message or error, then collect with idle timeout
    timeout_sec = timeout_ms / 1000.0
    start = time_module.time()

    # Wait for first message or error
    first_event = message_event.wait(timeout=timeout_sec) or error_event.is_set()

    if error_event.is_set():
        script.unload()
        return result

    # If we got a message, keep collecting until 200ms idle
    if first_event:
        while (time_module.time() - start) < timeout_sec:
            message_event.clear()
            # Wait 200ms for next message (idle detection)
            got_more = message_event.wait(timeout=0.2)
            if not got_more:
                break  # 200ms idle, we're done
            if error_event.is_set():
                break

    script.unload()
    return result


def install_hook(js_code: str, name: str = None) -> dict:
    """Install a persistent hook script that stays active and collects messages"""
    fs = get_session()

    script = fs.session.create_script(js_code)
    hook_name = name or f"hook_{len(fs.persistent_scripts)}"

    def on_message(message, data):
        if message["type"] == "send":
            fs.add_message(hook_name, message["payload"])
        elif message["type"] == "error":
            fs.add_message(hook_name, message["stack"], is_error=True)

    script.on("message", on_message)
    script.load()

    fs.persistent_scripts.append({"name": hook_name, "script": script})

    return {
        "status": "installed",
        "name": hook_name,
        "session_id": fs.id,
        "total_hooks": len(fs.persistent_scripts)
    }


def get_hook_messages(clear: bool = False) -> dict:
    """Get collected messages from persistent hooks"""
    fs = get_session()
    messages = fs.get_messages(clear=clear)
    return {
        "count": len(messages),
        "session_id": fs.id,
        "messages": messages
    }


def clear_hook_messages() -> dict:
    """Clear the hook message buffer"""
    fs = get_session()
    count = fs.clear_messages()
    return {"cleared": count, "session_id": fs.id}


def uninstall_hooks() -> dict:
    """Unload all persistent hook scripts"""
    fs = get_session()

    count = len(fs.persistent_scripts)
    for hook in fs.persistent_scripts:
        try:
            hook["script"].unload()
        except Exception:
            pass

    fs.persistent_scripts = []
    return {"uninstalled": count, "session_id": fs.id}


def list_hooks() -> list[dict]:
    """List all installed persistent hooks"""
    fs = get_session()
    return [{"name": h["name"], "index": i} for i, h in enumerate(fs.persistent_scripts)]


# ============================================================================
# HIGH-VALUE RE TOOLS
# ============================================================================

def get_module_base(name: str) -> dict:
    """Get base address of a module by name (partial match supported)"""
    js_code = '''
        var result = null;
        var pattern = ''' + json.dumps(name.lower()) + ''';
        Process.enumerateModules().forEach(function(m) {
            if (m.name.toLowerCase().indexOf(pattern) !== -1) {
                result = {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            }
        });
        send(result);
    '''
    return {"module": _run_script_sync(js_code)}


def hook_native(module: str, offset: str, name: str = None) -> dict:
    """Hook a native function by module name + offset. Returns hook messages via get_hook_messages()."""
    fs = get_session()

    hook_name = name or f"native_{module}_{offset}"

    js_code = '''
        var mod = null;
        var pattern = ''' + json.dumps(module.lower()) + ''';
        Process.enumerateModules().forEach(function(m) {
            if (m.name.toLowerCase().indexOf(pattern) !== -1) mod = m;
        });
        if (mod) {
            var addr = mod.base.add(''' + offset + ''');
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    var msg = "[''' + hook_name + '''] called";
                    try {
                        var a = [];
                        for (var i = 0; i < 6; i++) {
                            a.push("arg" + i + "=" + args[i]);
                        }
                        msg += " " + a.join(", ");
                    } catch(e) {}
                    send(msg);
                },
                onLeave: function(ret) {
                    send("[''' + hook_name + '''] returned: " + ret);
                }
            });
            send("[+] Hooked " + mod.name + " @ " + addr);
        } else {
            send("[-] Module not found: ''' + module + '''");
        }
    '''

    script = fs.session.create_script(js_code)
    def on_message(message, data):
        if message["type"] == "send":
            fs.add_message(hook_name, message["payload"])
        elif message["type"] == "error":
            fs.add_message(hook_name, message["stack"], is_error=True)

    script.on("message", on_message)
    script.load()
    fs.persistent_scripts.append({"name": hook_name, "script": script})

    return {"status": "installed", "name": hook_name, "module": module, "offset": offset, "session_id": fs.id}


def heap_search(class_name: str, max_results: int = 10) -> dict:
    """Search Java heap for instances of a class"""
    api = get_api()
    return _with_timeout(lambda: api.heap_search(class_name, max_results), timeout=10)


def memory_write(address: str, hex_bytes: str) -> dict:
    """Write bytes to memory address. hex_bytes should be hex string like 'deadbeef'"""
    js_code = '''
        var addr = ptr(''' + json.dumps(address) + ''');
        var bytes = ''' + json.dumps(hex_bytes) + ''';
        var arr = [];
        for (var i = 0; i < bytes.length; i += 2) {
            arr.push(parseInt(bytes.substr(i, 2), 16));
        }
        try {
            Memory.protect(addr, arr.length, 'rwx');
            Memory.writeByteArray(addr, arr);
            send({success: true, address: addr.toString(), bytes_written: arr.length});
        } catch(e) {
            send({success: false, error: e.message});
        }
    '''
    return _run_script_sync(js_code)


def dump_class(class_name: str) -> dict:
    """Dump all methods and fields of a Java class"""
    api = get_api()
    return _with_timeout(lambda: api.dump_class(class_name), timeout=10)




# ============================================================================
# AGENT SOURCE (compiled with frida-java-bridge)
# ============================================================================

# Cached agent source (loaded once on first use)
_agent_source_cache: str | None = None


def _get_agent_source() -> str:
    """Load the compiled Frida agent with Java bridge support (cached)"""
    global _agent_source_cache
    if _agent_source_cache is not None:
        return _agent_source_cache

    import os
    possible_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'agent', '_agent.js'),
        os.path.join(os.path.dirname(__file__), 'agent', '_agent.js'),
        '/Users/cbass/Code/objection-mcp/agent/_agent.js',
    ]

    for p in possible_paths:
        if os.path.exists(p):
            with open(p, 'r') as f:
                _agent_source_cache = f.read()
            return _agent_source_cache

    raise FileNotFoundError(
        "Compiled agent not found. Run 'npm run build' in the agent/ directory."
    )


# ============================================================================
# MCP SERVER
# ============================================================================

# Define all tools
TOOLS = [
    Tool(
        name="list_devices",
        description="List all available Frida devices (USB, remote, local)",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="list_processes",
        description="List running processes on a device",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device ID (optional, defaults to USB)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_apps",
        description="List installed applications on a device",
        inputSchema={
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device ID (optional, defaults to USB)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="connect",
        description="Connect to an app by bundle ID, name, or PID. Must call this before using other tools. When spawn=True, uses reliable adb-based launch instead of Frida spawn.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "App bundle ID, process name, or PID"},
                "device_id": {"type": "string", "description": "Device ID (optional)"},
                "spawn": {"type": "boolean", "description": "Spawn the app fresh (force stop + launch) before attaching (default: false)"},
                "timeout_ms": {"type": "integer", "description": "Timeout for waiting for app/Java to be ready in ms (default: 15000)"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="disconnect",
        description="Disconnect from the current session",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="is_connected",
        description="Check if Frida session is still alive and healthy. Returns connection status, PID, and device info.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="list_sessions",
        description="List all active Frida sessions. Supports multi-device workflows.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="switch_session",
        description="Switch to a different active session by ID. Use list_sessions to see available sessions.",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID to switch to"},
            },
            "required": ["session_id"],
        },
    ),
    Tool(
        name="get_pid",
        description="Get PID of a running app by package name. Useful before attaching with connect().",
        inputSchema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "App package name (e.g., 'com.spotify.music')"},
                "device_id": {"type": "string", "description": "Device ID (optional)"},
            },
            "required": ["package"],
        },
    ),
    Tool(
        name="launch_app",
        description="Launch an app via adb and return its PID (smart wait - polls for process).",
        inputSchema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "App package name (e.g., 'com.spotify.music')"},
                "activity": {"type": "string", "description": "Specific activity to launch (optional)"},
                "device_id": {"type": "string", "description": "Device ID (optional)"},
                "timeout_ms": {"type": "integer", "description": "Timeout for waiting for PID in ms (default: 10000)"},
            },
            "required": ["package"],
        },
    ),
    Tool(
        name="stop_app",
        description="Force stop an app by package name",
        inputSchema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "App package name to stop"},
                "device_id": {"type": "string", "description": "Device ID (optional)"},
            },
            "required": ["package"],
        },
    ),
    Tool(
        name="spawn_and_attach",
        description="Force stop app, launch fresh, and attach Frida. The reliable alternative to connect(spawn=True) which often times out.",
        inputSchema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "App package name (e.g., 'com.bestbuy.android')"},
                "device_id": {"type": "string", "description": "Device ID (optional)"},
                "wait_ms": {"type": "integer", "description": "Time to wait for app to start in ms (default: 3000)"},
            },
            "required": ["package"],
        },
    ),
    Tool(
        name="memory_list_modules",
        description="List all loaded modules (libraries) in the process",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="memory_list_exports",
        description="List exports (functions) from a specific module",
        inputSchema={
            "type": "object",
            "properties": {
                "module_name": {"type": "string", "description": "Name of the module (e.g., 'libc.so')"},
            },
            "required": ["module_name"],
        },
    ),
    Tool(
        name="memory_search",
        description="Search process memory for a pattern",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Hex pattern (e.g., '41 42 43') or string to search"},
                "is_string": {"type": "boolean", "description": "Treat pattern as string instead of hex (default: false)"},
            },
            "required": ["pattern"],
        },
    ),
    Tool(
        name="memory_read",
        description="Read memory at a specific address",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Memory address (e.g., '0x12345678')"},
                "size": {"type": "integer", "description": "Number of bytes to read"},
            },
            "required": ["address", "size"],
        },
    ),
    Tool(
        name="android_list_classes",
        description="List loaded Java classes, optionally filtered by pattern",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Filter pattern (e.g., 'crypto', 'javax')"},
            },
            "required": [],
        },
    ),
    Tool(
        name="android_list_methods",
        description="List methods of a Java class",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name (e.g., 'javax.crypto.Cipher')"},
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="android_hook_method",
        description="Hook a Java method to monitor calls. Logs arguments, return values, and optionally backtraces.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
                "method_name": {"type": "string", "description": "Method name (or '*' for all methods)"},
                "dump_args": {"type": "boolean", "description": "Log arguments (default: true)"},
                "dump_return": {"type": "boolean", "description": "Log return value (default: true)"},
                "dump_backtrace": {"type": "boolean", "description": "Log stack trace (default: false)"},
            },
            "required": ["class_name", "method_name"],
        },
    ),
    Tool(
        name="android_search_classes",
        description="Search for Java classes matching a pattern",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Search pattern (e.g., 'akamai', 'crypto')"},
            },
            "required": ["pattern"],
        },
    ),
    Tool(
        name="android_ssl_pinning_disable",
        description="Disable SSL certificate pinning to allow traffic interception",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="android_get_current_activity",
        description="Get the current foreground activity",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="file_ls",
        description="List files in a directory on the device",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path (default: current dir)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="file_read",
        description="Read a text file from the device",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path on device"},
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="file_download",
        description="Download a file from device to local machine",
        inputSchema={
            "type": "object",
            "properties": {
                "remote_path": {"type": "string", "description": "File path on device"},
                "local_path": {"type": "string", "description": "Local destination path"},
            },
            "required": ["remote_path", "local_path"],
        },
    ),
    Tool(
        name="run_script",
        description="Execute custom Frida JavaScript code. Java bridge is auto-imported, so Java.perform(), Java.use(), etc. work directly.",
        inputSchema={
            "type": "object",
            "properties": {
                "js_code": {"type": "string", "description": "JavaScript code to execute"},
            },
            "required": ["js_code"],
        },
    ),
    Tool(
        name="install_hook",
        description="Install a persistent hook script that stays active and collects messages. Use get_hook_messages to retrieve collected output.",
        inputSchema={
            "type": "object",
            "properties": {
                "js_code": {"type": "string", "description": "JavaScript hook code to install"},
                "name": {"type": "string", "description": "Optional name for this hook"},
            },
            "required": ["js_code"],
        },
    ),
    Tool(
        name="get_hook_messages",
        description="Get collected messages from persistent hooks installed via install_hook",
        inputSchema={
            "type": "object",
            "properties": {
                "clear": {"type": "boolean", "description": "Clear messages after retrieving (default: false)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="clear_hook_messages",
        description="Clear the hook message buffer without retrieving",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="uninstall_hooks",
        description="Unload all persistent hook scripts",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="list_hooks",
        description="List all installed persistent hooks with their names and indices",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_module_base",
        description="Get base address of a module by name (partial match). Returns {module: {name, base, size, path}}",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Module name or partial match (e.g., 'akamai', 'libc')"},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="hook_native",
        description="Hook a native function by module+offset. Messages collected via get_hook_messages().",
        inputSchema={
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Module name (partial match ok)"},
                "offset": {"type": "string", "description": "Hex offset from module base (e.g., '0x1234')"},
                "name": {"type": "string", "description": "Optional hook name for identification"},
            },
            "required": ["module", "offset"],
        },
    ),
    Tool(
        name="heap_search",
        description="Search Java heap for live instances of a class",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full Java class name (e.g., 'java.security.Key')"},
                "max_results": {"type": "integer", "description": "Max instances to return (default: 10)"},
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="memory_write",
        description="Write bytes to memory address (for patching)",
        inputSchema={
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Memory address (e.g., '0x12345678')"},
                "hex_bytes": {"type": "string", "description": "Hex bytes to write (e.g., 'deadbeef')"},
            },
            "required": ["address", "hex_bytes"],
        },
    ),
    Tool(
        name="dump_class",
        description="Dump all methods, fields, and constructors of a Java class",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full Java class name"},
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="run_java",
        description="Run arbitrary Java code within Java.performNow context. Has access to Java.use(), Java.choose(), send(), etc. Return value is the result of the last expression.",
        inputSchema={
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "JavaScript code to run within Java context"},
            },
            "required": ["code"],
        },
    ),
]


# Tool dispatcher
def call_tool(name: str, arguments: dict) -> Any:
    """Dispatch tool call to implementation"""

    if name == "list_devices":
        return list_devices()
    elif name == "list_processes":
        return list_processes(arguments.get("device_id"))
    elif name == "list_apps":
        return list_apps(arguments.get("device_id"))
    elif name == "connect":
        return connect(
            arguments["target"],
            arguments.get("device_id"),
            arguments.get("spawn", False),
            arguments.get("timeout_ms", 15000),
        )
    elif name == "disconnect":
        return disconnect()
    elif name == "is_connected":
        return is_connected()
    elif name == "list_sessions":
        return list_sessions()
    elif name == "switch_session":
        return switch_session(arguments["session_id"])
    elif name == "get_pid":
        return get_pid(arguments["package"], arguments.get("device_id"))
    elif name == "launch_app":
        return launch_app(
            arguments["package"],
            arguments.get("activity"),
            arguments.get("device_id"),
            arguments.get("timeout_ms", 10000),
        )
    elif name == "stop_app":
        return stop_app(arguments["package"], arguments.get("device_id"))
    elif name == "spawn_and_attach":
        return spawn_and_attach(
            arguments["package"],
            arguments.get("device_id"),
            arguments.get("wait_ms", 3000),
        )
    elif name == "memory_list_modules":
        return memory_list_modules()
    elif name == "memory_list_exports":
        return memory_list_exports(arguments["module_name"])
    elif name == "memory_search":
        return memory_search(arguments["pattern"], arguments.get("is_string", False))
    elif name == "memory_read":
        return memory_read(arguments["address"], arguments["size"])
    elif name == "android_list_classes":
        return android_list_classes(arguments.get("pattern"))
    elif name == "android_list_methods":
        return android_list_methods(arguments["class_name"])
    elif name == "android_hook_method":
        return android_hook_method(
            arguments["class_name"],
            arguments["method_name"],
            arguments.get("dump_args", True),
            arguments.get("dump_return", True),
            arguments.get("dump_backtrace", False),
        )
    elif name == "android_search_classes":
        return android_search_classes(arguments["pattern"])
    elif name == "android_ssl_pinning_disable":
        return android_ssl_pinning_disable()
    elif name == "android_get_current_activity":
        return android_get_current_activity()
    elif name == "file_ls":
        return file_ls(arguments.get("path", "."))
    elif name == "file_read":
        return file_read(arguments["path"])
    elif name == "file_download":
        return file_download(arguments["remote_path"], arguments["local_path"])
    elif name == "run_script":
        return run_script(arguments["js_code"])
    elif name == "install_hook":
        return install_hook(arguments["js_code"], arguments.get("name"))
    elif name == "get_hook_messages":
        return get_hook_messages(arguments.get("clear", False))
    elif name == "clear_hook_messages":
        return clear_hook_messages()
    elif name == "uninstall_hooks":
        return uninstall_hooks()
    elif name == "list_hooks":
        return list_hooks()
    elif name == "get_module_base":
        return get_module_base(arguments["name"])
    elif name == "hook_native":
        return hook_native(arguments["module"], arguments["offset"], arguments.get("name"))
    elif name == "heap_search":
        return heap_search(arguments["class_name"], arguments.get("max_results", 10))
    elif name == "memory_write":
        return memory_write(arguments["address"], arguments["hex_bytes"])
    elif name == "dump_class":
        return dump_class(arguments["class_name"])
    elif name == "run_java":
        return run_java(arguments["code"])
    else:
        raise ValueError(f"Unknown tool: {name}")


async def serve() -> None:
    """Run the MCP server"""
    server = Server("frida-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            result = call_tool(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options)


def main():
    """Entry point"""
    asyncio.run(serve())


if __name__ == "__main__":
    main()
