"""Memory operations."""

import json

from .session import get_api, get_session, with_timeout
from .hooks import run_script_sync


def memory_list_modules() -> list[dict]:
    """List loaded modules in the process."""
    api = get_api()
    return with_timeout(lambda: api.memory_list_modules())


def memory_list_exports(module_name: str) -> list[dict]:
    """List exports from a module."""
    api = get_api()
    return with_timeout(lambda: api.memory_list_exports(module_name))


def memory_search(pattern: str, is_string: bool = False) -> list[dict]:
    """Search memory for a pattern (hex bytes or string)."""
    api = get_api()
    return with_timeout(lambda: api.memory_search(pattern, is_string), timeout=10)


def memory_read(address: str, size: int) -> str:
    """Read memory at address, return as hex string."""
    api = get_api()
    return with_timeout(lambda: api.memory_read(address, size))


def memory_write(address: str, hex_bytes: str) -> dict:
    """Write bytes to memory address."""
    js_code = '''
        var addr = ptr(''' + json.dumps(address) + ''');
        var bytes = ''' + json.dumps(hex_bytes) + ''';
        var arr = [];
        for (var i = 0; i < bytes.length; i += 2) {
            arr.push(parseInt(bytes.substr(i, 2), 16));
        }
        try {
            Memory.protect(addr, arr.length, 'rwx');
            Memory.writeByteArray(addr, arr);
            send({success: true, address: addr.toString(), bytes_written: arr.length});
        } catch(e) {
            send({success: false, error: e.message});
        }
    '''
    return run_script_sync(js_code)


def get_module_base(name: str) -> dict:
    """Get base address of a module by name (partial match supported)."""
    js_code = '''
        var result = null;
        var pattern = ''' + json.dumps(name.lower()) + ''';
        Process.enumerateModules().forEach(function(m) {
            if (m.name.toLowerCase().indexOf(pattern) !== -1) {
                result = {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            }
        });
        send(result);
    '''
    return {"module": run_script_sync(js_code)}
