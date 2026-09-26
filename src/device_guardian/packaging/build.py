"""Packaging build script for Device Guardian (Phase 5).

Automates building a standalone executable using PyInstaller.
Usage:
    python -m device_guardian.packaging.build [--clean]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

from device_guardian.logger import get_logger

logger = get_logger("packaging.build")


def run_build(clean: bool = True, output_dir: str = "dist") -> bool:
    """Build the standalone executable with PyInstaller.

    Args:
        clean: Whether to wipe previous build and dist directories.
        output_dir: Name of directory to place compiled binary.

    Returns:
        True if build succeeded, False otherwise.
    """
    try:
        import PyInstaller.__main__
    except ImportError:
        logger.error("PyInstaller is not installed. Run: pip install pyinstaller")
        print("ERROR: PyInstaller is not installed. Run: pip install pyinstaller")
        return False

    spec_path = Path(__file__).resolve().parent / "device_guardian.spec"
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    dist_path = project_root / output_dir
    build_path = project_root / "build"

    if clean:
        print("[*] Cleaning build artifacts...")
        if build_path.is_dir():
            shutil.rmtree(build_path, ignore_errors=True)
        if dist_path.is_dir():
            shutil.rmtree(dist_path, ignore_errors=True)

    print(f"[*] Starting PyInstaller build using spec: {spec_path}...")

    args = [
        str(spec_path),
        f"--distpath={dist_path}",
        f"--workpath={build_path}",
        "--noconfirm",
    ]

    try:
        PyInstaller.__main__.run(args)
    except SystemExit as exc:
        if exc.code != 0:
            print(f"[!] PyInstaller exited with code: {exc.code}")
            return False
    except Exception as exc:
        print(f"[!] PyInstaller build failed: {exc}")
        return False

    # Verify output artifact
    binary_name = "device-guardian.exe" if sys.platform == "win32" else "device-guardian"
    target_binary = dist_path / binary_name

    if target_binary.is_file():
        size_bytes = target_binary.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        print(f"[+] Build SUCCESS! Executable created: {target_binary} ({size_mb:.2f} MB)")

        # Phase 7: Compute SHA-256 hash and generate release-manifest.json
        from datetime import datetime, timezone
        from device_guardian.updates.crypto import calculate_sha256
        from device_guardian.updates.manifest import ReleaseArtifact, ReleaseManifest
        from device_guardian.version import __version__, get_version_info

        v_info = get_version_info()
        sha256_hash = calculate_sha256(target_binary)
        print(f"[*] Artifact SHA-256: {sha256_hash}")

        artifact = ReleaseArtifact(
            filename=binary_name,
            platform=v_info.platform,
            architecture=v_info.architecture,
            sha256=sha256_hash,
            size_bytes=size_bytes,
        )

        manifest = ReleaseManifest(
            version=__version__,
            release_id=v_info.release_id,
            release_date=datetime.now(timezone.utc).isoformat(),
            platform=v_info.platform,
            architecture=v_info.architecture,
            artifacts=[artifact],
        )

        # Check for signing key in environment or arguments
        signing_key_hex = os.environ.get("DEVICE_GUARDIAN_SIGNING_KEY")
        if signing_key_hex:
            try:
                import binascii
                priv_bytes = binascii.unhexlify(signing_key_hex.strip())
                manifest.sign(priv_bytes)
                print(f"[+] Manifest digitally signed with Ed25519 signature.")
            except Exception as exc:
                print(f"[!] Warning: Failed to sign manifest: {exc}")

        manifest_path = dist_path / "release-manifest.json"
        manifest.save_to_file(manifest_path)
        print(f"[+] Release manifest generated at: {manifest_path}")

        # Phase 12: Artifact Secret Scanning
        clean_secrets, secret_issues = scan_artifacts_for_secrets(dist_path)
        if not clean_secrets:
            print("[!] CRITICAL: Secret scan detected sensitive material in build output:")
            for issue in secret_issues:
                print(f"    - {issue}")
            return False
        print("[+] Artifact secret scan passed: Zero sensitive credentials detected in release artifacts.")

        # Phase 12: Record Reproducible Build Metadata
        build_meta_path = dist_path / "build-metadata.json"
        import json
        build_meta = {
            "version": __version__,
            "release_id": v_info.release_id,
            "build_timestamp": datetime.now(timezone.utc).isoformat(),
            "python_version": sys.version.split()[0],
            "platform": v_info.platform,
            "architecture": v_info.architecture,
            "executable_name": binary_name,
            "executable_sha256": sha256_hash,
            "executable_size_bytes": size_bytes,
            "manifest_sha256": calculate_sha256(manifest_path),
        }
        build_meta_path.write_text(json.dumps(build_meta, indent=2), encoding="utf-8")
        print(f"[+] Reproducible build metadata recorded at: {build_meta_path}")

        return True
    else:
        print(f"[!] Build finished but expected binary not found at: {target_binary}")
        return False


def scan_artifacts_for_secrets(dist_dir: Path) -> tuple[bool, list[str]]:
    """Scan build output directory for forbidden secrets and private material."""
    issues = []
    import re
    token_pattern = re.compile(r"bot\d{6,12}:[A-Za-z0-9_-]{30,}")
    private_key_pattern = re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")

    for file_path in dist_dir.rglob("*"):
        if not file_path.is_file():
            continue
        # Forbid bundling real .env files or secret stores
        if file_path.name in {".env", "secrets.dat", "secrets.json"}:
            issues.append(f"Forbidden sensitive file found in output: {file_path.name}")
        # Only inspect text files for secret patterns
        if file_path.suffix in {".json", ".txt", ".md", ".yml", ".yaml", ".xml"}:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                if token_pattern.search(content):
                    issues.append(f"Potential bot token pattern detected in: {file_path.name}")
                if private_key_pattern.search(content):
                    issues.append(f"Private key header detected in: {file_path.name}")
            except Exception:
                pass
    return len(issues) == 0, issues



def main() -> None:
    """CLI entrypoint for packaging build script."""
    parser = argparse.ArgumentParser(description="Build Device Guardian standalone binary.")
    parser.add_argument("--clean", action="store_true", default=True, help="Clean previous build artifacts.")
    parser.add_argument("--no-clean", action="store_false", dest="clean", help="Do not clean build artifacts.")
    parser.add_argument("--output-dir", default="dist", help="Output distribution directory.")
    parser.add_argument("--signing-key", help="Hex-encoded 32-byte Ed25519 private signing key.")
    args = parser.parse_args()

    if args.signing_key:
        os.environ["DEVICE_GUARDIAN_SIGNING_KEY"] = args.signing_key

    success = run_build(clean=args.clean, output_dir=args.output_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
