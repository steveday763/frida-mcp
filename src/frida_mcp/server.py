#!/usr/bin/env python3
"""Frida MCP Server - Mobile security testing via Model Context Protocol."""

import json
import asyncio
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent

from .tools import TOOLS
from . import device, adb, memory, android, files, hooks


def call_tool(name: str, arguments: dict) -> Any:
    """Dispatch tool call to implementation."""

    # Device & connection
    if name == "list_devices":
        return device.list_devices()
    elif name == "list_processes":
        return device.list_processes(arguments.get("device_id"))
    elif name == "list_apps":
        return device.list_apps(arguments.get("device_id"))
    elif name == "connect":
        return device.connect(
            arguments["target"],
            arguments.get("device_id"),
            arguments.get("spawn", False),
            arguments.get("timeout_ms", 15000),
        )
    elif name == "disconnect":
        return device.disconnect()
    elif name == "is_connected":
        return device.is_connected()
    elif name == "list_sessions":
        return device.list_sessions()
    elif name == "switch_session":
        return device.switch_session(arguments["session_id"])

    # ADB app lifecycle
    elif name == "get_pid":
        return adb.get_pid(arguments["package"], arguments.get("device_id"))
    elif name == "launch_app":
        return adb.launch_app(
            arguments["package"],
            arguments.get("activity"),
            arguments.get("device_id"),
            arguments.get("timeout_ms", 10000),
        )
    elif name == "stop_app":
        return adb.stop_app(arguments["package"], arguments.get("device_id"))
    elif name == "spawn_and_attach":
        return device.spawn_and_attach(
            arguments["package"],
            arguments.get("device_id"),
            arguments.get("wait_ms", 3000),
        )

    # Memory
    elif name == "memory_list_modules":
        return memory.memory_list_modules()
    elif name == "memory_list_exports":
        return memory.memory_list_exports(arguments["module_name"])
    elif name == "memory_search":
        return memory.memory_search(arguments["pattern"], arguments.get("is_string", False))
    elif name == "memory_read":
        return memory.memory_read(arguments["address"], arguments["size"])
    elif name == "memory_write":
        return memory.memory_write(arguments["address"], arguments["hex_bytes"])
    elif name == "get_module_base":
        return memory.get_module_base(arguments["name"])

    # Android
    elif name == "android_list_classes":
        return android.android_list_classes(arguments.get("pattern"))
    elif name == "android_list_methods":
        return android.android_list_methods(arguments["class_name"])
    elif name == "android_hook_method":
        return android.android_hook_method(
            arguments["class_name"],
            arguments["method_name"],
            arguments.get("dump_args", True),
            arguments.get("dump_return", True),
            arguments.get("dump_backtrace", False),
        )
    elif name == "android_search_classes":
        return android.android_search_classes(arguments["pattern"])
    elif name == "android_ssl_pinning_disable":
        return android.android_ssl_pinning_disable()
    elif name == "android_get_current_activity":
        return android.android_get_current_activity()
    elif name == "dump_class":
        return android.dump_class(arguments["class_name"])
    elif name == "heap_search":
        return android.heap_search(arguments["class_name"], arguments.get("max_results", 10))
    elif name == "run_java":
        return android.run_java(arguments["code"])

    # Files
    elif name == "file_ls":
        return files.file_ls(arguments.get("path", "."))
    elif name == "file_read":
        return files.file_read(arguments["path"])
    elif name == "file_download":
        return files.file_download(arguments["remote_path"], arguments["local_path"])

    # Hooks
    elif name == "run_script":
        return hooks.run_script(arguments["js_code"])
    elif name == "install_hook":
        return hooks.install_hook(arguments["js_code"], arguments.get("name"))
    elif name == "get_hook_messages":
        return hooks.get_hook_messages(arguments.get("clear", False))
    elif name == "clear_hook_messages":
        return hooks.clear_hook_messages()
    elif name == "uninstall_hooks":
        return hooks.uninstall_hooks()
    elif name == "list_hooks":
        return hooks.list_hooks()
    elif name == "hook_native":
        return hooks.hook_native(arguments["module"], arguments["offset"], arguments.get("name"))

    else:
        raise ValueError(f"Unknown tool: {name}")


async def serve() -> None:
    """Run the MCP server."""
    server = Server("frida-mcp")

    @server.list_tools()
    async def list_tools():
        return TOOLS

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        try:
            result = call_tool(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options)


def main():
    """Entry point."""
    asyncio.run(serve())


if __name__ == "__main__":
    main()
