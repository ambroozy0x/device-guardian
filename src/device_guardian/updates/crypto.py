"""Cryptographic integrity and authenticity verification for Device Guardian (Phase 7).

Provides:
- Streaming SHA-256 calculation and verification.
- Pure-Python Ed25519 signature generation and verification conforming to RFC 8032.
- Deterministic JSON canonicalization for manifest signing.

Requires only the Python standard library (hashlib, os, hmac).
CRITICAL: Private signing keys must NEVER be stored in the repository, configuration,
logs, or packaged binaries.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Union

# =============================================================================
# 1. SHA-256 Streaming Integrity Utilities
# =============================================================================

def calculate_sha256(file_path: Union[Path, str], chunk_size: int = 65536) -> str:
    """Calculate the SHA-256 hash of a file using streaming reads.

    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (default: 64 KB).

    Returns:
        Lowercase hexadecimal SHA-256 digest string.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        IsADirectoryError: If the specified path is a directory.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        if path.is_dir():
            raise IsADirectoryError(f"Path is a directory, not a file: {path}")
        raise FileNotFoundError(f"File not found for SHA-256 calculation: {path}")

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_sha256(file_path: Union[Path, str], expected_hash: str) -> bool:
    """Verify that a file's SHA-256 digest matches the expected hash.

    Args:
        file_path: Path to the file to check.
        expected_hash: Expected lowercase or uppercase hex digest.

    Returns:
        True if hashes match exactly, False otherwise.
    """
    if not expected_hash or not isinstance(expected_hash, str):
        return False
    try:
        actual_hash = calculate_sha256(file_path)
        return actual_hash == expected_hash.strip().lower()
    except (FileNotFoundError, IsADirectoryError, OSError):
        return False


def canonicalize_json(data: dict) -> bytes:
    """Produce deterministic canonical JSON bytes for signature generation/verification."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


# =============================================================================
# 2. RFC 8032 Pure-Python Ed25519 Implementation
# =============================================================================

# Field parameters
_B = 256
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B_POINT = (_BX, _BY)


def _edwards_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    denom = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom) % _Q
    return (x3, y3)


def _scalar_mult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalar_mult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodepoint(P: tuple[int, int]) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(_B - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_B // 8))


def _decodepoint(s: bytes) -> Optional[tuple[int, int]]:
    if len(s) != 32:
        return None
    y = sum(s[i] << (i * 8) for i in range(_B // 8)) & ((1 << (_B - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[(_B - 1) // 8] >> 7) & 1):
        x = _Q - x
    P = (x, y)
    # Verify on curve: -x^2 + y^2 = 1 + d*x^2*y^2
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        return None
    return P


def generate_ed25519_keypair(seed: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Args:
        seed: Optional 32-byte secret seed. If None, os.urandom(32) is used.

    Returns:
        Tuple of (private_seed_bytes_32, public_key_bytes_32).
    """
    private_seed = seed if seed is not None else os.urandom(32)
    if len(private_seed) != 32:
        raise ValueError("Ed25519 private seed must be exactly 32 bytes.")

    h = hashlib.sha512(private_seed).digest()
    a = 2**(_B - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _B - 2))
    A = _scalar_mult(_B_POINT, a)
    public_key = _encodepoint(A)
    return private_seed, public_key


def sign_ed25519(message: bytes, private_seed: bytes, public_key: Optional[bytes] = None) -> bytes:
    """Sign an arbitrary message using an Ed25519 private key seed.

    Args:
        message: Raw bytes to sign.
        private_seed: 32-byte private key seed.
        public_key: Optional public key bytes (derived automatically if omitted).

    Returns:
        64-byte Ed25519 signature.
    """
    if len(private_seed) != 32:
        raise ValueError("Ed25519 private key must be exactly 32 bytes.")

    h = hashlib.sha512(private_seed).digest()
    a = 2**(_B - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _B - 2))
    A = _scalar_mult(_B_POINT, a)
    public_key = _encodepoint(A)

    r_digest = hashlib.sha512(h[32:] + message).digest()
    r = int.from_bytes(r_digest, "little") % _L

    R = _scalar_mult(_B_POINT, r)
    R_bytes = _encodepoint(R)

    k_digest = hashlib.sha512(R_bytes + public_key + message).digest()
    k = int.from_bytes(k_digest, "little") % _L

    S = (r + k * a) % _L
    S_bytes = S.to_bytes(32, "little")

    return R_bytes + S_bytes


def verify_ed25519(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature over a message using a public verification key.

    Args:
        message: Raw bytes that were signed.
        signature: 64-byte Ed25519 signature.
        public_key: 32-byte public key.

    Returns:
        True if the signature is authentic and valid, False otherwise.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False

    R_bytes = signature[:32]
    S_bytes = signature[32:]
    S = int.from_bytes(S_bytes, "little")
    if S >= _L:
        return False

    A = _decodepoint(public_key)
    if A is None:
        return False

    R = _decodepoint(R_bytes)
    if R is None:
        return False

    k_digest = hashlib.sha512(R_bytes + public_key + message).digest()
    k = int.from_bytes(k_digest, "little") % _L

    # Verify: 8 * S * B = 8 * R + 8 * k * A
    SB = _scalar_mult(_B_POINT, S)
    kA = _scalar_mult(A, k)
    R_plus_kA = _edwards_add(R, kA)

    return _encodepoint(SB) == _encodepoint(R_plus_kA)


# Aliases for API compatibility
generate_keypair = generate_ed25519_keypair
ed25519_sign = sign_ed25519
ed25519_verify = verify_ed25519
