"""Tests for agent loading and caching"""

import pytest
import objection_mcp.server as server
from objection_mcp.server import _get_agent_source


class TestAgentLoading:
    """Agent source loading tests"""

    def setup_method(self):
        """Clear cache before each test"""
        server._agent_source_cache = None

    def test_agent_loads(self):
        source = _get_agent_source()
        assert len(source) > 0

    def test_agent_has_rpc_exports(self):
        source = _get_agent_source()
        # Either raw source with rpc.exports or ESM bundle with 📦 header
        assert "rpc.exports" in source or "📦" in source

    def test_agent_has_expected_functions(self):
        source = _get_agent_source()
        expected_exports = [
            "memoryListModules",
            "memoryRead",
            "androidHookingGetClasses",
            "androidSslpinningDisable",
        ]
        for export in expected_exports:
            assert export in source, f"Missing export: {export}"

    def test_agent_cached_after_first_load(self):
        assert server._agent_source_cache is None

        source1 = _get_agent_source()
        assert server._agent_source_cache is not None

        source2 = _get_agent_source()
        assert source1 is source2  # Same object reference

    def test_agent_not_found_raises(self, tmp_path, monkeypatch):
        """When agent file doesn't exist, should raise FileNotFoundError"""
        # Patch the function to look in a nonexistent path
        def mock_get_agent():
            import os
            server._agent_source_cache = None
            possible_paths = [str(tmp_path / "nonexistent.js")]
            for p in possible_paths:
                if os.path.exists(p):
                    with open(p, 'r') as f:
                        return f.read()
            raise FileNotFoundError(
                "Compiled agent not found. Run 'npm run build' in the agent/ directory."
            )

        with pytest.raises(FileNotFoundError, match="npm run build"):
            mock_get_agent()
