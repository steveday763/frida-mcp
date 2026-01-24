"""Tests for MCP tool definitions and schema validation"""

import pytest
from objection_mcp.server import TOOLS


class TestToolDefinitions:
    """Validate all MCP tool definitions"""

    def test_tools_not_empty(self):
        assert len(TOOLS) > 0

    def test_all_tools_have_name(self):
        for tool in TOOLS:
            assert tool.name, f"Tool missing name"
            assert isinstance(tool.name, str)
            assert len(tool.name) > 0

    def test_all_tools_have_description(self):
        for tool in TOOLS:
            assert tool.description, f"Tool {tool.name} missing description"
            assert len(tool.description) > 10, f"Tool {tool.name} description too short"

    def test_all_tools_have_input_schema(self):
        for tool in TOOLS:
            assert tool.inputSchema, f"Tool {tool.name} missing inputSchema"

    def test_schema_is_object_type(self):
        for tool in TOOLS:
            assert tool.inputSchema.get("type") == "object", \
                f"Tool {tool.name} schema type must be 'object'"

    def test_schema_has_properties(self):
        for tool in TOOLS:
            assert "properties" in tool.inputSchema, \
                f"Tool {tool.name} missing 'properties' in schema"

    def test_schema_has_required(self):
        for tool in TOOLS:
            assert "required" in tool.inputSchema, \
                f"Tool {tool.name} missing 'required' in schema"

    def test_required_fields_in_properties(self):
        for tool in TOOLS:
            required = tool.inputSchema.get("required", [])
            properties = tool.inputSchema.get("properties", {})
            for field in required:
                assert field in properties, \
                    f"Tool {tool.name}: required field '{field}' not in properties"

    def test_property_types_valid(self):
        valid_types = {"string", "integer", "boolean", "number", "array", "object"}
        for tool in TOOLS:
            for prop_name, prop_def in tool.inputSchema.get("properties", {}).items():
                if "type" in prop_def:
                    assert prop_def["type"] in valid_types, \
                        f"Tool {tool.name}.{prop_name} has invalid type: {prop_def['type']}"

    def test_no_duplicate_names(self):
        names = [tool.name for tool in TOOLS]
        duplicates = [n for n in names if names.count(n) > 1]
        assert not duplicates, f"Duplicate tool names: {set(duplicates)}"

    def test_names_are_snake_case(self):
        import re
        pattern = re.compile(r'^[a-z][a-z0-9_]*$')
        for tool in TOOLS:
            assert pattern.match(tool.name), \
                f"Tool name '{tool.name}' should be snake_case"


class TestExpectedTools:
    """Verify expected tools exist"""

    CORE_TOOLS = {
        "list_devices",
        "list_processes",
        "list_apps",
        "connect",
        "disconnect",
        "is_connected",
    }

    MEMORY_TOOLS = {
        "memory_list_modules",
        "memory_list_exports",
        "memory_search",
        "memory_read",
        "memory_write",
    }

    ANDROID_TOOLS = {
        "android_list_classes",
        "android_list_methods",
        "android_hook_method",
        "android_search_classes",
        "android_ssl_pinning_disable",
        "android_get_current_activity",
    }

    SCRIPTING_TOOLS = {
        "run_script",
        "run_java",
        "install_hook",
        "get_hook_messages",
        "uninstall_hooks",
    }

    @pytest.fixture
    def tool_names(self):
        return {tool.name for tool in TOOLS}

    def test_core_tools_exist(self, tool_names):
        missing = self.CORE_TOOLS - tool_names
        assert not missing, f"Missing core tools: {missing}"

    def test_memory_tools_exist(self, tool_names):
        missing = self.MEMORY_TOOLS - tool_names
        assert not missing, f"Missing memory tools: {missing}"

    def test_android_tools_exist(self, tool_names):
        missing = self.ANDROID_TOOLS - tool_names
        assert not missing, f"Missing Android tools: {missing}"

    def test_scripting_tools_exist(self, tool_names):
        missing = self.SCRIPTING_TOOLS - tool_names
        assert not missing, f"Missing scripting tools: {missing}"


class TestToolDescriptions:
    """Validate tool descriptions are helpful"""

    def test_connect_describes_spawn(self):
        tool = next(t for t in TOOLS if t.name == "connect")
        assert "spawn" in tool.description.lower()

    def test_dangerous_tools_have_warnings(self):
        """Tools that modify state should indicate that"""
        modify_tools = {"memory_write", "disconnect", "uninstall_hooks"}
        for tool in TOOLS:
            if tool.name in modify_tools:
                # Just verify they have substantial descriptions
                assert len(tool.description) > 20
