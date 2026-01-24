"""Android/Java hooking operations."""

from .session import get_api, with_timeout


def android_list_classes(pattern: str | None = None) -> list[str]:
    """List loaded Java classes, optionally filtered by pattern."""
    api = get_api()
    classes = with_timeout(lambda: api.android_hooking_get_classes(), timeout=10)
    if pattern:
        pattern_lower = pattern.lower()
        classes = [c for c in classes if pattern_lower in c.lower()]
    return classes[:500]


def android_list_methods(class_name: str) -> list[str]:
    """List methods of a Java class."""
    api = get_api()
    return with_timeout(lambda: api.android_hooking_get_class_methods(class_name))


def android_hook_method(
    class_name: str,
    method_name: str,
    dump_args: bool = True,
    dump_return: bool = True,
    dump_backtrace: bool = False,
) -> dict:
    """Hook a Java method to monitor calls."""
    api = get_api()
    target = f"{class_name}!{method_name}"
    api.android_hooking_watch(target, dump_args, dump_backtrace, dump_return)
    return {"status": "hooked", "target": target}


def android_search_classes(pattern: str) -> list[dict]:
    """Search for classes matching pattern."""
    api = get_api()
    return with_timeout(lambda: api.android_hooking_enumerate(pattern), timeout=10)


def android_ssl_pinning_disable() -> dict:
    """Disable SSL certificate pinning."""
    api = get_api()
    api.android_sslpinning_disable()
    return {"status": "ssl_pinning_disabled"}


def android_get_current_activity() -> str:
    """Get the current foreground activity."""
    api = get_api()
    return with_timeout(lambda: api.android_hooking_get_current_activity())


def dump_class(class_name: str) -> dict:
    """Dump all methods and fields of a Java class."""
    api = get_api()
    return with_timeout(lambda: api.dump_class(class_name), timeout=10)


def heap_search(class_name: str, max_results: int = 10) -> dict:
    """Search Java heap for instances of a class."""
    api = get_api()
    return with_timeout(lambda: api.heap_search(class_name, max_results), timeout=10)


def run_java(code: str):
    """Run arbitrary Java code within Java.performNow context."""
    api = get_api()
    return with_timeout(lambda: api.run_java(code), timeout=10)
