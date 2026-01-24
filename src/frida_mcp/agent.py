"""Frida agent loader."""

import os

_agent_source_cache: str | None = None


def get_agent_source() -> str:
    """Load the compiled Frida agent with Java bridge support (cached)."""
    global _agent_source_cache
    if _agent_source_cache is not None:
        return _agent_source_cache

    possible_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'agent', '_agent.js'),
        os.path.join(os.path.dirname(__file__), 'agent', '_agent.js'),
        '/Users/cbass/Code/frida-mcp/agent/_agent.js',
    ]

    for p in possible_paths:
        if os.path.exists(p):
            with open(p, 'r') as f:
                _agent_source_cache = f.read()
            return _agent_source_cache

    raise FileNotFoundError(
        "Compiled agent not found. Run 'npm run build' in the agent/ directory."
    )
