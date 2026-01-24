"""File operations on device."""

from .session import get_api, with_timeout


def file_ls(path: str = ".") -> list[dict]:
    """List files in directory."""
    api = get_api()
    return with_timeout(lambda: api.file_ls(path))


def file_read(path: str) -> str:
    """Read a file from the device."""
    api = get_api()
    return with_timeout(lambda: api.file_read(path))


def file_download(remote_path: str, local_path: str) -> dict:
    """Download a file from device to local machine."""
    api = get_api()
    data = with_timeout(lambda: api.file_download(remote_path), timeout=30)
    with open(local_path, 'wb') as f:
        f.write(bytes(data))
    return {"status": "downloaded", "path": local_path, "size": len(data)}
