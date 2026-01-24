"""Device and connection management."""

import sys
import time as time_module

import frida

from .session import registry, get_session
from .adb import adb_shell, ensure_selinux_permissive, wait_for_pid
from .agent import get_agent_source


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
        frida_session = device.attach(pid)
        target_name = target
    except ValueError:
        if spawn:
            # Force stop the app
            adb_shell(["am", "force-stop", target], device_id)

            # Wait for process to die
            for _ in range(10):
                time_module.sleep(0.2)
                if not adb_shell(["pidof", target], device_id):
                    break

            time_module.sleep(0.3)

            # Launch via monkey
            adb_shell([
                "monkey", "-p", target,
                "-c", "android.intent.category.LAUNCHER", "1"
            ], device_id)

            # Wait for PID
            pid = wait_for_pid(target, device_id, timeout_ms)
            frida_session = device.attach(pid)
            spawn_method = "adb_launch"
        else:
            frida_session = device.attach(target)
        target_name = target

    # Load agent
    agent_source = get_agent_source()
    script = frida_session.create_script(agent_source)

    actual_pid = pid
    if actual_pid is None:
        try:
            actual_pid = frida_session._impl.pid
        except Exception:
            actual_pid = 0

    script.load()
    api = script.exports_sync

    # Register session
    fs = registry.create(
        device=device,
        session=frida_session,
        api=api,
        target=target_name,
        pid=actual_pid,
    )

    # Message handler
    def on_message(message, data):
        if message["type"] == "send":
            payload = message['payload']
            display = str(payload)[:200] + '...' if len(str(payload)) > 200 else str(payload)
            print(f"[FRIDA] {display}", file=sys.stderr)
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
