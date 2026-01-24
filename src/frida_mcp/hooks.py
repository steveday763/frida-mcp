"""Hook and script operations."""

import json
import time as time_module
from threading import Event, Lock

from .session import get_session


def run_script_sync(js_code: str, timeout_ms: int = 5000):
    """Run a Frida script and wait for it to send a result."""
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


def run_script(js_code: str, timeout_ms: int = 2000):
    """Execute custom Frida JavaScript code and collect messages."""
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

    timeout_sec = timeout_ms / 1000.0
    start = time_module.time()

    first_event = message_event.wait(timeout=timeout_sec) or error_event.is_set()

    if error_event.is_set():
        script.unload()
        return result

    if first_event:
        while (time_module.time() - start) < timeout_sec:
            message_event.clear()
            got_more = message_event.wait(timeout=0.2)
            if not got_more:
                break
            if error_event.is_set():
                break

    script.unload()
    return result


def install_hook(js_code: str, name: str = None) -> dict:
    """Install a persistent hook script that stays active and collects messages."""
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
    """Get collected messages from persistent hooks."""
    fs = get_session()
    messages = fs.get_messages(clear=clear)
    return {
        "count": len(messages),
        "session_id": fs.id,
        "messages": messages
    }


def clear_hook_messages() -> dict:
    """Clear the hook message buffer."""
    fs = get_session()
    count = fs.clear_messages()
    return {"cleared": count, "session_id": fs.id}


def uninstall_hooks() -> dict:
    """Unload all persistent hook scripts."""
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
    """List all installed persistent hooks."""
    fs = get_session()
    return [{"name": h["name"], "index": i} for i, h in enumerate(fs.persistent_scripts)]


def hook_native(module: str, offset: str, name: str = None) -> dict:
    """Hook a native function by module name + offset."""
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
