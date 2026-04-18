"""ADB helpers for app lifecycle management."""

import subprocess
import time as time_module


def _run_adb(args: list[str]) -> str:
    """Run adb and decode output robustly on Windows."""
    result = subprocess.run(args, capture_output=True)
    if result.stdout:
        return result.stdout.decode("utf-8", errors="replace").strip()
    return ""


def adb_shell(cmd: list[str], device_id: str | None = None) -> str:
    """Run adb shell command and return output."""
    args = ["adb"]
    if device_id:
        args.extend(["-s", device_id])
    args.extend(["shell"] + cmd)
    return _run_adb(args)


def adb_cmd(cmd: list[str], device_id: str | None = None) -> str:
    """Run adb command (not shell) and return output."""
    args = ["adb"]
    if device_id:
        args.extend(["-s", device_id])
    args.extend(cmd)
    return _run_adb(args)


def ensure_selinux_permissive(device_id: str | None = None) -> str:
    """Set SELinux to permissive mode (required for Frida on some devices)."""
    current = adb_shell(["su", "-c", "getenforce"], device_id)
    if current.lower() == "permissive":
        return "already_permissive"
    adb_shell(["su", "-c", "setenforce 0"], device_id)
    new_mode = adb_shell(["su", "-c", "getenforce"], device_id)
    return f"set_to_{new_mode.lower()}"


def wait_for_pid(package: str, device_id: str | None, timeout_ms: int = 10000) -> int:
    """Poll for PID to appear after launching app."""
    start = time_module.time()
    while (time_module.time() - start) * 1000 < timeout_ms:
        pid_output = adb_shell(["pidof", package], device_id)
        if pid_output:
            return int(pid_output.split()[0])
        time_module.sleep(0.2)
    raise RuntimeError(f"Timeout waiting for {package} to start")


def get_pid(package: str, device_id: str | None = None) -> dict:
    """Get PID of running app by package name."""
    output = adb_shell(["pidof", package], device_id)
    if output:
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
    """Launch app via adb and return its PID."""
    if activity:
        component = f"{package}/{activity}" if not activity.startswith(package) else activity
        output = adb_shell(["am", "start", "-n", component], device_id)
    else:
        output = adb_shell([
            "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1"
        ], device_id)

    try:
        pid = wait_for_pid(package, device_id, timeout_ms)
    except RuntimeError:
        pid = None

    return {
        "package": package,
        "activity": activity,
        "pid": pid,
        "output": output,
    }


def stop_app(package: str, device_id: str | None = None) -> dict:
    """Force stop an app."""
    output = adb_shell(["am", "force-stop", package], device_id)
    return {"package": package, "stopped": True, "output": output}
