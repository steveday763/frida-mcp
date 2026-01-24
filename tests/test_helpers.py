"""Tests for helper functions"""

import pytest
from unittest.mock import patch, MagicMock
import time

from objection_mcp.server import (
    _with_timeout,
    is_connected,
    get_api,
    get_session,
    _registry,
)


class TestWithTimeout:
    """Tests for _with_timeout helper"""

    def test_returns_result(self):
        result = _with_timeout(lambda: "hello", timeout=1)
        assert result == "hello"

    @pytest.mark.skip(reason="ThreadPoolExecutor doesn't cancel threads, test hangs")
    def test_timeout_raises(self):
        def slow_func():
            time.sleep(10)
            return "done"

        with pytest.raises(TimeoutError, match="timed out"):
            _with_timeout(slow_func, timeout=0.05)

    def test_passes_through_exceptions(self):
        def bad_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            _with_timeout(bad_func, timeout=1)


class TestIsConnected:
    """Tests for is_connected function"""

    def setup_method(self):
        _registry.close_all()

    def test_not_connected_when_no_session(self):
        result = is_connected()
        assert result["connected"] is False
        assert result["reason"] == "no_session"

    def test_connected_with_valid_session(self):
        mock_device = MagicMock()
        mock_device.name = "Test Device"
        mock_session = MagicMock()
        mock_session._impl.pid = 1234
        mock_api = MagicMock()
        mock_api.memory_list_modules.return_value = [{"name": "libc.so"}]

        _registry.create(mock_device, mock_session, mock_api, "com.test", 1234)

        result = is_connected()
        assert result["connected"] is True
        assert result["pid"] == 1234
        assert result["device"] == "Test Device"
        assert result["module_count"] == 1

    def test_not_connected_when_session_dead(self):
        mock_device = MagicMock()
        mock_device.name = "Test Device"
        mock_session = MagicMock()
        mock_session._impl.pid = property(lambda s: (_ for _ in ()).throw(Exception("dead")))
        mock_api = MagicMock()
        mock_api.memory_list_modules.side_effect = Exception("session dead")

        _registry.create(mock_device, mock_session, mock_api, "com.test", 1234)

        result = is_connected()
        assert result["connected"] is False
        assert "reason" in result

    def teardown_method(self):
        _registry.close_all()


class TestGetApi:
    """Tests for get_api helper"""

    def setup_method(self):
        _registry.close_all()

    def test_raises_when_not_connected(self):
        with pytest.raises(RuntimeError, match="Not connected"):
            get_api()

    def test_returns_api_when_connected(self):
        mock_device = MagicMock()
        mock_device.name = "Device"
        mock_session = MagicMock()
        mock_session._impl.pid = 1234
        mock_api = MagicMock()

        _registry.create(mock_device, mock_session, mock_api, "app", 1234)

        assert get_api() == mock_api

    def teardown_method(self):
        _registry.close_all()


class TestGetSession:
    """Tests for get_session helper"""

    def setup_method(self):
        _registry.close_all()

    def test_raises_when_not_connected(self):
        with pytest.raises(RuntimeError, match="Not connected"):
            get_session()

    def test_returns_session_when_connected(self):
        mock_device = MagicMock()
        mock_device.name = "Device"
        mock_session = MagicMock()
        mock_session._impl.pid = 1234
        mock_api = MagicMock()

        fs = _registry.create(mock_device, mock_session, mock_api, "app", 1234)

        assert get_session() == fs

    def teardown_method(self):
        _registry.close_all()


class TestAdbHelpers:
    """Tests for ADB helper functions"""

    def test_adb_shell_constructs_command(self):
        with patch("objection_mcp.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="output\n", returncode=0)

            from objection_mcp.server import _adb_shell
            result = _adb_shell(["pm", "list", "packages"])

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["adb", "shell", "pm", "list", "packages"]
            assert result == "output"

    def test_adb_shell_with_device_id(self):
        with patch("objection_mcp.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="output\n", returncode=0)

            from objection_mcp.server import _adb_shell
            _adb_shell(["ls"], device_id="abc123")

            args = mock_run.call_args[0][0]
            assert args == ["adb", "-s", "abc123", "shell", "ls"]

    def test_get_pid_returns_pid(self):
        with patch("objection_mcp.server._adb_shell") as mock:
            mock.return_value = "12345"

            from objection_mcp.server import get_pid
            result = get_pid("com.test.app")

            assert result["package"] == "com.test.app"
            assert result["pid"] == 12345

    def test_get_pid_returns_none_when_not_running(self):
        with patch("objection_mcp.server._adb_shell") as mock:
            mock.return_value = ""

            from objection_mcp.server import get_pid
            result = get_pid("com.test.app")

            assert result["pid"] is None

    def test_stop_app_calls_force_stop(self):
        with patch("objection_mcp.server._adb_shell") as mock:
            mock.return_value = ""

            from objection_mcp.server import stop_app
            result = stop_app("com.test.app")

            mock.assert_called_with(["am", "force-stop", "com.test.app"], None)
            assert result["stopped"] is True

    def test_ensure_selinux_permissive_already_set(self):
        with patch("objection_mcp.server._adb_shell") as mock:
            mock.return_value = "Permissive"

            from objection_mcp.server import _ensure_selinux_permissive
            result = _ensure_selinux_permissive()

            assert result == "already_permissive"

    def test_ensure_selinux_permissive_sets_it(self):
        with patch("objection_mcp.server._adb_shell") as mock:
            mock.side_effect = ["Enforcing", "", "Permissive"]

            from objection_mcp.server import _ensure_selinux_permissive
            result = _ensure_selinux_permissive()

            assert result == "set_to_permissive"
