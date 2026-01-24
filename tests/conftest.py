"""Shared test fixtures"""

import pytest
from unittest.mock import MagicMock

from objection_mcp.server import SessionRegistry, FridaSession


@pytest.fixture
def mock_device():
    """Mock Frida device"""
    device = MagicMock()
    device.name = "Test Device"
    device.id = "test-device-id"
    device.type = "usb"
    return device


@pytest.fixture
def mock_frida_session():
    """Mock Frida session"""
    session = MagicMock()
    session._impl.pid = 1234
    return session


@pytest.fixture
def mock_api():
    """Mock Frida RPC API"""
    return MagicMock()


@pytest.fixture
def frida_session(mock_device, mock_frida_session, mock_api):
    """Create a FridaSession for testing"""
    return FridaSession(
        id="test-session",
        device=mock_device,
        session=mock_frida_session,
        api=mock_api,
        target="com.test.app",
        pid=1234,
    )


@pytest.fixture
def registry():
    """Fresh SessionRegistry for testing"""
    return SessionRegistry()


@pytest.fixture
def registry_with_session(registry, mock_device, mock_frida_session, mock_api):
    """SessionRegistry with one session already created"""
    registry.create(mock_device, mock_frida_session, mock_api, "com.test.app", 1234)
    return registry
