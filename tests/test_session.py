"""Tests for session management (SessionRegistry, FridaSession)"""

import pytest
from unittest.mock import MagicMock


class TestSessionRegistry:
    """SessionRegistry unit tests"""

    def test_empty_registry(self, registry):
        assert registry.get_active() is None
        assert registry.list_sessions() == []

    def test_create_session(self, registry, mock_device, mock_frida_session, mock_api):
        fs = registry.create(mock_device, mock_frida_session, mock_api, "com.test.app", 1234)

        assert fs.target == "com.test.app"
        assert fs.pid == 1234
        assert registry.get_active() == fs

    def test_create_sets_active(self, registry, mock_device, mock_frida_session, mock_api):
        fs1 = registry.create(mock_device, mock_frida_session, mock_api, "app1", 1000)
        assert registry.get_active() == fs1

        fs2 = registry.create(mock_device, mock_frida_session, mock_api, "app2", 2000)
        assert registry.get_active() == fs2  # New session becomes active

    def test_get_by_id(self, registry, mock_device, mock_frida_session, mock_api):
        fs = registry.create(mock_device, mock_frida_session, mock_api, "app", 1000)
        assert registry.get(fs.id) == fs
        assert registry.get("nonexistent") is None

    def test_switch_session(self, registry, mock_device, mock_frida_session, mock_api):
        fs1 = registry.create(mock_device, mock_frida_session, mock_api, "app1", 1000)
        fs2 = registry.create(mock_device, mock_frida_session, mock_api, "app2", 2000)

        assert registry.set_active(fs1.id)
        assert registry.get_active() == fs1

    def test_switch_invalid_session(self, registry):
        assert not registry.set_active("nonexistent")

    def test_remove_session(self, registry_with_session):
        session = registry_with_session.get_active()
        session_id = session.id

        assert registry_with_session.remove(session_id)
        assert registry_with_session.get_active() is None
        assert registry_with_session.get(session_id) is None

    def test_remove_switches_active(self, registry, mock_device, mock_frida_session, mock_api):
        fs1 = registry.create(mock_device, mock_frida_session, mock_api, "app1", 1000)
        fs2 = registry.create(mock_device, mock_frida_session, mock_api, "app2", 2000)

        registry.remove(fs2.id)
        assert registry.get_active() == fs1  # Falls back to remaining session

    def test_remove_nonexistent(self, registry):
        assert not registry.remove("nonexistent")

    def test_remove_active(self, registry_with_session):
        assert registry_with_session.remove_active()
        assert registry_with_session.get_active() is None

    def test_remove_active_when_none(self, registry):
        assert not registry.remove_active()

    def test_list_sessions(self, registry, mock_device, mock_frida_session, mock_api):
        fs1 = registry.create(mock_device, mock_frida_session, mock_api, "app1", 1000)
        fs2 = registry.create(mock_device, mock_frida_session, mock_api, "app2", 2000)

        sessions = registry.list_sessions()
        assert len(sessions) == 2

        targets = {s["target"] for s in sessions}
        assert targets == {"app1", "app2"}

        # Check active flag
        active_sessions = [s for s in sessions if s["active"]]
        assert len(active_sessions) == 1
        assert active_sessions[0]["target"] == "app2"

    def test_close_all(self, registry, mock_device, mock_frida_session, mock_api):
        registry.create(mock_device, mock_frida_session, mock_api, "app1", 1000)
        registry.create(mock_device, mock_frida_session, mock_api, "app2", 2000)

        registry.close_all()

        assert registry.get_active() is None
        assert len(registry.list_sessions()) == 0


class TestFridaSession:
    """FridaSession unit tests"""

    def test_add_message(self, frida_session):
        frida_session.add_message("hook1", {"key": "value"})

        messages = frida_session.get_messages()
        assert len(messages) == 1
        assert messages[0]["hook"] == "hook1"
        assert messages[0]["payload"] == {"key": "value"}
        assert "ts" in messages[0]

    def test_add_error_message(self, frida_session):
        frida_session.add_message("hook1", "error text", is_error=True)

        messages = frida_session.get_messages()
        assert len(messages) == 1
        assert "error" in messages[0]
        assert messages[0]["error"] == "error text"

    def test_message_truncation(self, frida_session):
        long_payload = "x" * 20000
        frida_session.add_message("hook1", long_payload)

        messages = frida_session.get_messages()
        assert len(messages[0]["payload"]) == 10000 + len("...[truncated]")
        assert messages[0]["payload"].endswith("...[truncated]")

    def test_message_cap_at_100(self, frida_session):
        for i in range(150):
            frida_session.add_message("hook", f"msg{i}")

        # Internal buffer capped at 100
        assert len(frida_session.hook_messages) == 100

    def test_get_messages_returns_last_50(self, frida_session):
        for i in range(100):
            frida_session.add_message("hook", f"msg{i}")

        messages = frida_session.get_messages()
        assert len(messages) == 50

    def test_get_messages_with_clear(self, frida_session):
        frida_session.add_message("hook", "data")

        messages = frida_session.get_messages(clear=True)
        assert len(messages) == 1
        assert len(frida_session.get_messages()) == 0

    def test_clear_messages(self, frida_session):
        frida_session.add_message("hook", "data1")
        frida_session.add_message("hook", "data2")

        count = frida_session.clear_messages()
        assert count == 2
        assert len(frida_session.hook_messages) == 0

    def test_is_alive(self, frida_session):
        assert frida_session.is_alive()

    def test_is_alive_when_dead(self, frida_session):
        # Make accessing pid raise an exception
        type(frida_session.session._impl).pid = property(lambda self: (_ for _ in ()).throw(Exception("dead")))
        assert not frida_session.is_alive()

    def test_detach_cleans_up(self, frida_session):
        # Add a mock persistent script
        mock_script = MagicMock()
        frida_session.persistent_scripts.append({"name": "test", "script": mock_script})

        frida_session.detach()

        mock_script.unload.assert_called_once()
        assert len(frida_session.persistent_scripts) == 0
        frida_session.session.detach.assert_called_once()

    def test_detach_handles_errors(self, frida_session):
        mock_script = MagicMock()
        mock_script.unload.side_effect = Exception("already unloaded")
        frida_session.persistent_scripts.append({"name": "test", "script": mock_script})

        # Should not raise
        frida_session.detach()
        assert len(frida_session.persistent_scripts) == 0
