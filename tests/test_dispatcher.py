"""Tests for call_tool dispatcher"""

import pytest
from unittest.mock import patch, MagicMock

from objection_mcp.server import call_tool, TOOLS


class TestDispatcherRouting:
    """Test that dispatcher routes to correct functions"""

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            call_tool("nonexistent_tool", {})

    def test_all_tools_have_dispatcher_entry(self):
        """Every defined tool should be handled by dispatcher"""
        for tool in TOOLS:
            # Mock all possible functions to avoid actual execution
            with patch.multiple(
                "objection_mcp.server",
                list_devices=MagicMock(return_value=[]),
                list_processes=MagicMock(return_value=[]),
                list_apps=MagicMock(return_value=[]),
                connect=MagicMock(return_value={}),
                disconnect=MagicMock(return_value={}),
                is_connected=MagicMock(return_value={}),
                list_sessions=MagicMock(return_value=[]),
                switch_session=MagicMock(return_value={}),
                get_pid=MagicMock(return_value={}),
                launch_app=MagicMock(return_value={}),
                stop_app=MagicMock(return_value={}),
                spawn_and_attach=MagicMock(return_value={}),
                memory_list_modules=MagicMock(return_value=[]),
                memory_list_exports=MagicMock(return_value=[]),
                memory_search=MagicMock(return_value=[]),
                memory_read=MagicMock(return_value=""),
                memory_write=MagicMock(return_value={}),
                android_list_classes=MagicMock(return_value=[]),
                android_list_methods=MagicMock(return_value=[]),
                android_hook_method=MagicMock(return_value={}),
                android_search_classes=MagicMock(return_value=[]),
                android_ssl_pinning_disable=MagicMock(return_value={}),
                android_get_current_activity=MagicMock(return_value=""),
                file_ls=MagicMock(return_value=[]),
                file_read=MagicMock(return_value=""),
                file_download=MagicMock(return_value={}),
                run_script=MagicMock(return_value={}),
                install_hook=MagicMock(return_value={}),
                get_hook_messages=MagicMock(return_value={}),
                clear_hook_messages=MagicMock(return_value={}),
                uninstall_hooks=MagicMock(return_value={}),
                list_hooks=MagicMock(return_value=[]),
                get_module_base=MagicMock(return_value={}),
                hook_native=MagicMock(return_value={}),
                heap_search=MagicMock(return_value={}),
                dump_class=MagicMock(return_value={}),
                get_akamai_signal=MagicMock(return_value=""),
                bypass_akamai_debug=MagicMock(return_value=[]),
                run_java=MagicMock(return_value=None),
            ):
                # Build minimal required args
                schema = tool.inputSchema
                args = {}
                for field in schema.get("required", []):
                    prop = schema["properties"].get(field, {})
                    prop_type = prop.get("type", "string")
                    if prop_type == "string":
                        args[field] = "test"
                    elif prop_type == "integer":
                        args[field] = 1
                    elif prop_type == "boolean":
                        args[field] = True

                # Should not raise ValueError for unknown tool
                try:
                    call_tool(tool.name, args)
                except ValueError as e:
                    if "Unknown tool" in str(e):
                        pytest.fail(f"Tool '{tool.name}' not handled by dispatcher")


class TestDispatcherArguments:
    """Test that dispatcher passes arguments correctly"""

    def test_connect_passes_all_args(self):
        with patch("objection_mcp.server.connect") as mock:
            mock.return_value = {"status": "connected"}
            call_tool("connect", {
                "target": "com.test.app",
                "device_id": "abc123",
                "spawn": True,
                "timeout_ms": 5000,
            })
            mock.assert_called_once_with("com.test.app", "abc123", True, 5000)

    def test_connect_uses_defaults(self):
        with patch("objection_mcp.server.connect") as mock:
            mock.return_value = {"status": "connected"}
            call_tool("connect", {"target": "com.test.app"})
            mock.assert_called_once_with("com.test.app", None, False, 15000)

    def test_memory_read_passes_args(self):
        with patch("objection_mcp.server.memory_read") as mock:
            mock.return_value = "deadbeef"
            call_tool("memory_read", {"address": "0x1000", "size": 16})
            mock.assert_called_once_with("0x1000", 16)

    def test_android_hook_method_passes_args(self):
        with patch("objection_mcp.server.android_hook_method") as mock:
            mock.return_value = {"status": "hooked"}
            call_tool("android_hook_method", {
                "class_name": "com.test.Class",
                "method_name": "doSomething",
                "dump_args": False,
                "dump_return": True,
                "dump_backtrace": True,
            })
            mock.assert_called_once_with(
                "com.test.Class", "doSomething", False, True, True
            )

    def test_android_hook_method_defaults(self):
        with patch("objection_mcp.server.android_hook_method") as mock:
            mock.return_value = {"status": "hooked"}
            call_tool("android_hook_method", {
                "class_name": "com.test.Class",
                "method_name": "doSomething",
            })
            mock.assert_called_once_with(
                "com.test.Class", "doSomething", True, True, False
            )

    def test_file_ls_default_path(self):
        with patch("objection_mcp.server.file_ls") as mock:
            mock.return_value = []
            call_tool("file_ls", {})
            mock.assert_called_once_with(".")

    def test_heap_search_default_max(self):
        with patch("objection_mcp.server.heap_search") as mock:
            mock.return_value = {"instances": []}
            call_tool("heap_search", {"class_name": "java.lang.String"})
            mock.assert_called_once_with("java.lang.String", 10)

    def test_spawn_and_attach_passes_args(self):
        with patch("objection_mcp.server.spawn_and_attach") as mock:
            mock.return_value = {"status": "connected"}
            call_tool("spawn_and_attach", {
                "package": "com.test.app",
                "device_id": "device1",
                "wait_ms": 5000,
            })
            mock.assert_called_once_with("com.test.app", "device1", 5000)


class TestDispatcherReturnValues:
    """Test that dispatcher returns function results"""

    def test_returns_list(self):
        with patch("objection_mcp.server.list_devices") as mock:
            expected = [{"id": "test", "name": "Device", "type": "usb"}]
            mock.return_value = expected
            result = call_tool("list_devices", {})
            assert result == expected

    def test_returns_dict(self):
        with patch("objection_mcp.server.connect") as mock:
            expected = {"status": "connected", "pid": 1234}
            mock.return_value = expected
            result = call_tool("connect", {"target": "app"})
            assert result == expected

    def test_returns_string(self):
        with patch("objection_mcp.server.memory_read") as mock:
            mock.return_value = "deadbeef"
            result = call_tool("memory_read", {"address": "0x1000", "size": 8})
            assert result == "deadbeef"
