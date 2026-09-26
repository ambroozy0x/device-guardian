"""Device Guardian packaging package (Phase 5)."""

def run_build(*args, **kwargs):
    from device_guardian.packaging.build import run_build as _run_build
    return _run_build(*args, **kwargs)

__all__ = ["run_build"]
