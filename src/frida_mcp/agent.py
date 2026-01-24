"""Frida agent loader."""

import os

_agent_source_cache: str | None = None


def get_agent_source() -> str:
    """Load the compiled Frida agent with Java bridge support (cached)."""
    global _agent_source_cache
    if _agent_source_cache is not None:
        return _agent_source_cache

    # Check env var first, then relative paths
    possible_paths = []

    if env_path := os.environ.get("FRIDA_MCP_AGENT_PATH"):
        possible_paths.append(env_path)

    possible_paths.extend([
        os.path.join(os.path.dirname(__file__), '..', '..', 'agent', '_agent.js'),
        os.path.join(os.path.dirname(__file__), 'agent', '_agent.js'),
    ])

    for p in possible_paths:
        if os.path.exists(p):
            with open(p, 'r') as f:
                _agent_source_cache = f.read()
            return _agent_source_cache

    raise FileNotFoundError(
        "Compiled agent not found. Run 'npm run build' in the agent/ directory, "
        "or set FRIDA_MCP_AGENT_PATH environment variable."
    )
