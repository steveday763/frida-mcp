# frida-mcp

MCP server for Frida-based mobile security testing. Exposes Frida functionality as MCP tools for AI-assisted security research.

## Requirements

- Python 3.11+
- Frida server running on target device
- ADB access for Android devices
- Rooted device (for most operations)

## Install

```bash
cd frida-mcp
uv pip install -e .
```

Build the Frida agent (required):

```bash
cd agent
npm install
npm run build
```

The compiled agent now bundles `frida-java-bridge` via npm and should be rebuilt after changing anything under [`agent/`](./agent).

## Add to Claude Code

```bash
claude mcp add frida-mcp -- frida-mcp
```

## Tools

### Connection & Session Management

| Tool | Description |
|------|-------------|
| `list_devices` | List all available Frida devices (USB, remote, local) |
| `list_processes` | List running processes on a device |
| `list_apps` | List installed applications on a device |
| `connect` | Attach to app by bundle ID, name, or PID. Supports `spawn=true` for fresh launch. |
| `disconnect` | Disconnect from the current session |
| `is_connected` | Check if Frida session is still alive and healthy |
| `list_sessions` | List all active Frida sessions (multi-device support) |
| `switch_session` | Switch to a different active session by ID |

### App Lifecycle (ADB-based)

| Tool | Description |
|------|-------------|
| `get_pid` | Get PID of a running app by package name |
| `launch_app` | Launch app via ADB and return its PID |
| `stop_app` | Force stop an app by package name |
| `spawn_and_attach` | Force stop, launch fresh, and attach Frida in one step |

### Memory Operations

| Tool | Description |
|------|-------------|
| `memory_list_modules` | List all loaded modules (libraries) in the process |
| `memory_list_exports` | List exports (functions) from a specific module |
| `memory_search` | Search process memory for hex pattern or string |
| `memory_read` | Read memory at a specific address |
| `memory_write` | Write bytes to memory address (for patching) |
| `get_module_base` | Get base address of a module by name (partial match) |

### Android Java Hooking

| Tool | Description |
|------|-------------|
| `android_list_classes` | List loaded Java classes, optionally filtered |
| `android_list_methods` | List methods of a Java class |
| `android_hook_method` | Hook a Java method to monitor calls |
| `android_search_classes` | Search for classes matching a pattern |
| `android_ssl_pinning_disable` | Disable SSL certificate pinning |
| `android_get_current_activity` | Get the current foreground activity |
| `dump_class` | Dump all methods, fields, and constructors of a class |
| `heap_search` | Search Java heap for live instances of a class |

### Persistent Hooks

| Tool | Description |
|------|-------------|
| `install_hook` | Install a persistent hook script that collects messages |
| `get_hook_messages` | Retrieve collected messages from persistent hooks |
| `clear_hook_messages` | Clear the hook message buffer |
| `uninstall_hooks` | Unload all persistent hook scripts |
| `list_hooks` | List all installed persistent hooks |
| `hook_native` | Hook a native function by module+offset |

### File Operations

| Tool | Description |
|------|-------------|
| `file_ls` | List files in a directory on the device |
| `file_read` | Read a text file from the device |
| `file_download` | Download a file from device to local machine |

### Custom Scripting

| Tool | Description |
|------|-------------|
| `run_script` | Execute custom Frida JavaScript code |
| `run_java` | Run JavaScript within Java.performNow context |

## Usage Example

```
1. list_devices          → Find your device
2. connect target=com.example.app spawn=true  → Attach to app
3. android_search_classes pattern=crypto      → Find crypto classes
4. android_hook_method class_name=... method_name=...  → Hook methods
5. get_hook_messages     → See captured calls
```

## Notes

- SELinux is automatically set to permissive mode when connecting (required for Frida injection on many devices)
- `connect(..., spawn=true)` and `spawn_and_attach` now prefer Frida's native `spawn -> attach -> load agent -> resume` flow, and fall back to ADB launch if native spawn is unavailable
- Agent bootstrap waits for the compiled script to report readiness before exposing RPC exports, which avoids transient session initialization failures on Android
- The active session keeps the main agent script alive for the lifetime of the connection
- On Windows, ADB output and the compiled agent source are decoded as UTF-8 to avoid locale-dependent failures
- Multi-session support allows attaching to multiple apps/devices simultaneously

## Android Notes

- When `pidof` returns multiple PIDs for one package, connection logic retries and waits for a stable attach target instead of assuming the first PID is correct
- `memory_read` returns a lowercase hex string and uses a bulk `readByteArray()` path internally, which is significantly faster than byte-by-byte reads for larger ranges
- Java-backed tools such as `android_*` and `file_*` require the compiled agent in [`agent/_agent.js`](./agent/_agent.js) to be up to date

## Troubleshooting

- If Java tools fail unexpectedly, rebuild the agent:

```bash
cd agent
npm install
npm run build
```

- If MCP is using a custom launcher, point `FRIDA_MCP_AGENT_PATH` at the compiled [`agent/_agent.js`](./agent/_agent.js)
- If Android attach works intermittently on fresh launches, prefer `spawn=true` or `spawn_and_attach` over launching the app externally and attaching later
