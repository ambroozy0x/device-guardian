"""Test-only failure injection framework for Device Guardian resilience testing (Phase 8).

Strictly test-scoped. Never imported by production modules.
Provides context managers to deterministically simulate faults:
- Filesystem errors (I/O, permissions, disk full)
- Corrupted JSON / empty state files
- Transient and permanent network failures
- HTTP error responses (429, 500, 502, 503)
- Background worker thread crashes
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import Any, Generator, Optional
from unittest.mock import MagicMock, patch

import requests


@contextmanager
def inject_filesystem_error(
    target_function: str = "os.replace",
    error_type: type[Exception] = OSError,
    error_message: str = "Injected filesystem I/O error",
) -> Generator[MagicMock, None, None]:
    """Context manager to simulate filesystem operations failing."""
    with patch(target_function, side_effect=error_type(error_message)) as mock_func:
        yield mock_func


@contextmanager
def inject_corrupted_json(
    file_path: Path | str,
    corrupt_content: str = "{invalid_json_missing_brace: true",
) -> Generator[Path, None, None]:
    """Context manager that writes corrupted content to a file, then cleans up."""
    path = Path(file_path)
    original_bytes: Optional[bytes] = path.read_bytes() if path.is_file() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(corrupt_content, encoding="utf-8")
    try:
        yield path
    finally:
        if original_bytes is not None:
            path.write_bytes(original_bytes)
        elif path.is_file():
            path.unlink()


@contextmanager
def inject_network_timeout(
    target_function: str = "requests.post",
    error_message: str = "Injected network timeout",
) -> Generator[MagicMock, None, None]:
    """Context manager to simulate network timeout."""
    with patch(target_function, side_effect=requests.exceptions.Timeout(error_message)) as mock_net:
        yield mock_net


@contextmanager
def inject_network_connection_error(
    target_function: str = "requests.post",
    error_message: str = "Injected network connection error",
) -> Generator[MagicMock, None, None]:
    """Context manager to simulate network connection drop."""
    with patch(target_function, side_effect=requests.exceptions.ConnectionError(error_message)) as mock_net:
        yield mock_net


@contextmanager
def inject_http_error(
    status_code: int = 500,
    target_function: str = "requests.post",
    response_data: Optional[dict[str, Any]] = None,
) -> Generator[MagicMock, None, None]:
    """Context manager to simulate an HTTP error response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = response_data or {
        "ok": False,
        "description": f"Injected HTTP {status_code} error",
    }
    mock_resp.text = f"HTTP {status_code} Error"
    with patch(target_function, return_value=mock_resp) as mock_func:
        yield mock_func
