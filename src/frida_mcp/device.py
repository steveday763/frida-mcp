"""Device and connection management."""

import sys
import time as time_module
from threading import Event

import frida

from .session import registry
from .adb import adb_shell, ensure_selinux_permissive, wait_for_pid
from .agent import get_agent_source

_ATTACH_RETRYABLE_ERRORS = tuple(
    exc for exc in (
        getattr(frida, "ProcessNotFoundError", None),
        getattr(frida, "ProcessNotRespondingError", None),
        getattr(frida, "TimedOutError", None),
        getattr(frida, "TransportError", None),
    ) if exc is not None
)


def _resolve_pid(target: str, device_id: str | None = None) -> int | None:
    """Resolve a package/process name to a live PID using adb."""
    pid_output = adb_shell(["pidof", target], device_id)
    if not pid_output:
        return None
    try:
        return int(pid_output.split()[0])
    except ValueError:
        return None


def _wait_for_stable_pid(
    target: str,
    device_id: str | None,
    timeout_ms: int,
    stable_reads: int = 3,
    poll_interval_s: float = 0.25,
) -> int | None:
    """Wait until pidof returns the same PID repeatedly, indicating the process settled."""
    deadline = time_module.time() + (timeout_ms / 1000.0)
    last_pid: int | None = None
    consecutive = 0

    while time_module.time() < deadline:
        pid = _resolve_pid(target, device_id)
        if pid is None:
            last_pid = None
            consecutive = 0
        elif pid == last_pid:
            consecutive += 1
            if consecutive >= stable_reads:
                return pid
        else:
            last_pid = pid
            consecutive = 1

        time_module.sleep(poll_interval_s)

    return last_pid


def _wait_for_process_visible(
    device: frida.core.Device,
    pid: int,
    timeout_ms: int,
    poll_interval_s: float = 0.2,
) -> bool:
    """Wait until Frida's device view can enumerate the target PID."""
    deadline = time_module.time() + (timeout_ms / 1000.0)
    while time_module.time() < deadline:
        try:
            if any(proc.pid == pid for proc in device.enumerate_processes()):
                return True
        except Exception:
            pass
        time_module.sleep(poll_interval_s)
    return False


def _attach_with_retry(
    device: frida.core.Device,
    target: str | int,
    timeout_ms: int,
    device_id: str | None = None,
) -> tuple[frida.core.Session, int | None]:
    """Attach with retries to smooth over Android process startup races."""
    deadline = time_module.time() + (timeout_ms / 1000.0)
    last_error: Exception | None = None

    while time_module.time() < deadline:
        try:
            if isinstance(target, int):
                _wait_for_process_visible(device, target, timeout_ms=min(1200, max(400, timeout_ms)))
                return device.attach(target), target
            resolved_pid = _wait_for_stable_pid(
                target,
                device_id,
                timeout_ms=min(1500, max(600, timeout_ms)),
            )
            if resolved_pid is not None:
                _wait_for_process_visible(
                    device,
                    resolved_pid,
                    timeout_ms=1200,
                )
                return device.attach(resolved_pid), resolved_pid
            return device.attach(target), None
        except _ATTACH_RETRYABLE_ERRORS as e:
            last_error = e

            # If the string target is actually a package name, resolve the live PID and retry.
            if isinstance(target, str):
                pid = _wait_for_stable_pid(
                    target,
                    device_id,
                    timeout_ms=1000,
                    stable_reads=2,
                    poll_interval_s=0.2,
                )
                if pid is not None:
                    try:
                        _wait_for_process_visible(
                            device,
                            pid,
                            timeout_ms=1000,
                        )
                        return device.attach(pid), pid
                    except _ATTACH_RETRYABLE_ERRORS as inner:
                        last_error = inner

            time_module.sleep(0.35)

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"Timed out attaching to {target}")


def _make_message_handler(
    ready_event: Event,
    bootstrap_messages: list[str],
    session_holder: dict,
):
    """Create a script message handler that buffers startup messages until registration."""

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            payload_text = str(payload)
            display = payload_text[:200] + '...' if len(payload_text) > 200 else payload_text
            print(f"[FRIDA] {display}", file=sys.stderr)

            if payload_text == "[+] frida-mcp agent loaded":
                ready_event.set()

            if isinstance(payload, str) and payload.startswith('['):
                fs = session_holder.get("session")
                if fs is None:
                    bootstrap_messages.append(payload)
                else:
                    fs.add_message("agent", payload)
        elif message["type"] == "error":
            print(f"[ERROR] {message.get('stack', message)}", file=sys.stderr)

    return on_message


def _load_agent_with_retry(
    frida_session: frida.core.Session,
    agent_source: str,
    timeout_ms: int,
) -> tuple[frida.core.Script, object, list[str], dict]:
    """Load the agent and wait for its bootstrap message before syncing RPC exports."""
    deadline = time_module.time() + (timeout_ms / 1000.0)
    last_error: Exception | None = None

    while time_module.time() < deadline:
        ready_event = Event()
        bootstrap_messages: list[str] = []
        session_holder: dict = {"session": None}
        script = frida_session.create_script(agent_source)
        script.on("message", _make_message_handler(ready_event, bootstrap_messages, session_holder))

        try:
            script.load()
            remaining = max(0.1, deadline - time_module.time())
            ready_event.wait(min(remaining, 3.0))
            if not ready_event.is_set():
                time_module.sleep(0.2)

            api = script.exports_sync
            return script, api, bootstrap_messages, session_holder
        except Exception as e:
            last_error = e
            try:
                script.unload()
            except Exception:
                pass
            time_module.sleep(0.25)

    if last_error is not None:
        raise last_error
    raise RuntimeError("Timed out loading Frida agent")


def _spawn_package(
    device: frida.core.Device,
    package: str,
    timeout_ms: int,
    device_id: str | None = None,
) -> tuple[frida.core.Session, int, str]:
    """Spawn via Frida first; fall back to adb launch if spawn is unavailable."""
    try:
        pid = device.spawn([package])
        return device.attach(pid), pid, "frida_spawn"
    except Exception:
        adb_shell(["am", "force-stop", package], device_id)

        for _ in range(10):
            time_module.sleep(0.2)
            if not adb_shell(["pidof", package], device_id):
                break

        time_module.sleep(0.3)
        adb_shell([
            "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1"
        ], device_id)

        wait_for_pid(package, device_id, timeout_ms)
        frida_session, resolved_pid = _attach_with_retry(
            device,
            package,
            timeout_ms=max(timeout_ms, 5000),
            device_id=device_id,
        )
        actual_pid = resolved_pid if resolved_pid is not None else 0
        return frida_session, actual_pid, "adb_launch"


def list_devices() -> list[dict]:
    """List all available Frida devices."""
    devices = []
    for device in frida.enumerate_devices():
        devices.append({
            "id": device.id,
            "name": device.name,
            "type": device.type,
        })
    return devices


def list_processes(device_id: str | None = None) -> list[dict]:
    """List processes on a device."""
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
    """List installed applications on a device."""
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


def connect(
    target: str,
    device_id: str | None = None,
    spawn: bool = False,
    timeout_ms: int = 15000,
) -> dict:
    """Connect to an app by name/bundle ID or PID."""
    # Disconnect existing active session
    active = registry.get_active()
    if active:
        registry.remove(active.id)

    # Get device
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=10)

    # Ensure SELinux is permissive
    selinux_status = ensure_selinux_permissive(device_id)

    # Determine if target is PID or name
    pid = None
    spawn_method = None
    try:
        pid = int(target)
        frida_session, resolved_pid = _attach_with_retry(device, pid, timeout_ms, device_id)
        if resolved_pid is not None:
            pid = resolved_pid
        target_name = target
    except ValueError:
        if spawn:
            frida_session, pid, spawn_method = _spawn_package(
                device,
                target,
                timeout_ms,
                device_id,
            )
        else:
            frida_session, resolved_pid = _attach_with_retry(device, target, timeout_ms, device_id)
            if resolved_pid is not None:
                pid = resolved_pid
        target_name = target

    # Load agent
    agent_source = get_agent_source()
    script, api, bootstrap_messages, session_holder = _load_agent_with_retry(
        frida_session,
        agent_source,
        timeout_ms=max(timeout_ms, 5000),
    )

    actual_pid = pid
    if actual_pid is None:
        try:
            actual_pid = frida_session._impl.pid
        except Exception:
            actual_pid = 0

    # Register session
    fs = registry.create(
        device=device,
        session=frida_session,
        script=script,
        api=api,
        target=target_name,
        pid=actual_pid,
    )
    session_holder["session"] = fs
    for payload in bootstrap_messages:
        fs.add_message("agent", payload)

    if spawn_method == "frida_spawn" and actual_pid:
        device.resume(actual_pid)

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
    """Disconnect from current session."""
    active = registry.get_active()
    if active:
        session_id = active.id
        registry.remove(session_id)
        return {"status": "disconnected", "session_id": session_id}
    return {"status": "not_connected"}


def list_sessions() -> list[dict]:
    """List all active Frida sessions."""
    return registry.list_sessions()


def switch_session(session_id: str) -> dict:
    """Switch to a different active session by ID."""
    if registry.set_active(session_id):
        fs = registry.get(session_id)
        return {
            "status": "switched",
            "session_id": session_id,
            "target": fs.target if fs else None,
            "pid": fs.pid if fs else None,
        }
    return {"status": "error", "message": f"Session {session_id} not found"}


def is_connected() -> dict:
    """Check if Frida session is still alive and healthy."""
    fs = registry.get_active()
    if fs is None:
        return {"connected": False, "reason": "no_session"}

    try:
        pid = fs.session._impl.pid
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


def spawn_and_attach(
    package: str,
    device_id: str | None = None,
    wait_ms: int = 5000,
) -> dict:
    """Force stop app, launch fresh, and attach Frida."""
    return connect(package, device_id, spawn=True, timeout_ms=wait_ms)
