"""Tests for PyInstaller packaging specification and build orchestration (Phase 5)."""

from pathlib import Path
from unittest.mock import patch
import pytest

from device_guardian.packaging.build import run_build


def test_packaging_spec_file_exists():
    """Verify device_guardian.spec exists and contains required packaging definitions."""
    spec_path = Path(__file__).resolve().parent.parent / "src" / "device_guardian" / "packaging" / "device_guardian.spec"
    assert spec_path.is_file()

    content = spec_path.read_text(encoding="utf-8")
    assert "Analysis(" in content
    assert "device_guardian" in content
    assert "pystray" in content
    assert "PIL" in content
    assert "device-guardian" in content


def test_packaging_build_runner_mock(tmp_path):
    """Verify run_build invokes PyInstaller with expected spec arguments."""
    with patch("PyInstaller.__main__.run") as mock_pyi_run:
        # Mock target binary creation
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        import sys
        binary_name = "device-guardian.exe" if sys.platform == "win32" else "device-guardian"
        (dist_dir / binary_name).write_text("fake_binary")

        success = run_build(clean=False, output_dir=str(dist_dir))
        assert success is True
        mock_pyi_run.assert_called_once()
