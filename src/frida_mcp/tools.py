"""MCP tool definitions."""

from mcp.types import Tool

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
