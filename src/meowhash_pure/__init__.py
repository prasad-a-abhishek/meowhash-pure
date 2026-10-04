# meowhash-pure: pure-Python MeowHash 0.6 implementation
# MeowHash — Aumasson & Bohn, 2019 — AES-NI-based non-cryptographic hash
#
# Reference sources:
#   Canonical C: https://github.com/NoHatCoder/Meow-Hash-0.6-Candidate (public domain)
#   Rust impl:   https://github.com/bodil/meowhash-rs (MPL 2.0)
#   Paper:       https://mollyrocket.com/meowhash
#
# Public API (Invariant 21 — total over arbitrary input):
#   meow64(data: bytes, seed: int = 0) -> int
#   meow128(data: bytes, seed: int = 0) -> tuple[int, int]
#   class State128:
#       def __init__(self, seed: int = 0) -> None
#       def absorb(self, chunk: bytes) -> None
#       def finalize(self) -> int
#   expand_seed(key: bytes) -> bytes

from __future__ import annotations

import hashlib
import struct
from typing import Tuple

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
__all__ = ['meow64', 'meow128', 'State128', 'expand_seed', 'MeowHashError']

# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class MeowHashError(Exception):
    """Raised when MeowHash receives invalid input."""
    pass


# ---------------------------------------------------------------------------
# AES S-box
# ---------------------------------------------------------------------------
_AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])


def _subbytes(state: list[int]) -> list[int]:
    return [_AES_SBOX[b] for b in state]


def _inv_subbytes(state: list[int]) -> list[int]:
    inv = [0] * 256
    for i in range(256):
        inv[_AES_SBOX[i]] = i
    inv_sbox = bytes(inv)
    return [inv_sbox[b] for b in state]


def _shiftrows(state: list[int]) -> list[int]:
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]


def _inv_shiftrows(state: list[int]) -> list[int]:
    return [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3],
    ]


def _mixcolumn(col: list[int]) -> list[int]:
    a, b, c, d = col
    return [
        (0x02 * a ^ 0x03 * b ^ c ^ d) & 0xff,
        (a ^ 0x02 * b ^ 0x03 * c ^ d) & 0xff,
        (a ^ b ^ 0x02 * c ^ 0x03 * d) & 0xff,
        (0x03 * a ^ b ^ c ^ 0x02 * d) & 0xff,
    ]


def _mixcolumns(state: list[int]) -> list[int]:
    return (
        _mixcolumn(state[0:4]) + _mixcolumn(state[4:8]) +
        _mixcolumn(state[8:12]) + _mixcolumn(state[12:16])
    )


def _addroundkey(state: list[int], key: list[int]) -> list[int]:
    return [state[i] ^ key[i] for i in range(16)]


def _aes_round(state: list[int], round_key: list[int]) -> list[int]:
    return _addroundkey(_mixcolumns(_shiftrows(_subbytes(state))), round_key)


def _aesenc(a: list[int], b: list[int], round_key: list[int]) -> list[int]:
    xored = [a[i] ^ b[i] for i in range(16)]
    return _aes_round(xored, round_key)


def _aesdec(a: list[int], round_key: list[int]) -> list[int]:
    # AESDEC = InvShiftRows → InvSubBytes → AddRoundKey (no InvMixColumns)
    shifted = _inv_shiftrows(a)
    subbed = _inv_subbytes(shifted)
    return [subbed[i] ^ round_key[i] for i in range(16)]


def _load16(data: bytes) -> list[int]:
    return list(data[:16])


def _xor_state(a: list[int], b: list[int]) -> list[int]:
    return [a[i] ^ b[i] for i in range(16)]


def _add_u64(a: list[int], b: list[int]) -> list[int]:
    """Add two 128-bit values as packed uint64 lanes (mod 2^64 each)."""
    lo_a = int.from_bytes(bytes(a[:8]), 'little')
    hi_a = int.from_bytes(bytes(a[8:16]), 'little')
    lo_b = int.from_bytes(bytes(b[:8]), 'little')
    hi_b = int.from_bytes(bytes(b[8:16]), 'little')
    lo = (lo_a + lo_b) & ((1 << 64) - 1)
    hi = (hi_a + hi_b) & ((1 << 64) - 1)
    return list(int.to_bytes(lo, 8, 'little')) + list(int.to_bytes(hi, 8, 'little'))


# ---------------------------------------------------------------------------
# Default seed (pi encoding, 176 bytes)
# ---------------------------------------------------------------------------
_MEOW_DEFAULT_SEED = bytes([
    0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
    0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
    0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D,
    0x00, 0x82, 0xEF, 0xA9, 0x8E, 0xC4, 0xE6, 0xC8,
    0x94, 0x52, 0x82, 0x1E, 0x63, 0x8D, 0x01, 0x37,
    0x7B, 0xE5, 0x46, 0x6C, 0xF3, 0x4E, 0x90, 0xC6,
    0xCC, 0x0A, 0xC2, 0x9B, 0x7C, 0x97, 0xC5, 0x0D,
    0xD3, 0xF8, 0x4D, 0x5B, 0x5B, 0x54, 0x70, 0x91,
    0x79, 0x21, 0x6D, 0x5D, 0x98, 0x97, 0x9F, 0xB1,
    0xBD, 0x13, 0x10, 0xBA, 0x69, 0x8D, 0xFB, 0x5A,
    0xC2, 0xFF, 0xD7, 0x2D, 0xBD, 0x01, 0xAD, 0xFB,
    0x7B, 0x8E, 0x1A, 0xFE, 0xD6, 0xA2, 0x67, 0xE9,
    0x6B, 0xA7, 0xC9, 0x04, 0x5F, 0x12, 0xC7, 0xF9,
    0x92, 0x4A, 0x19, 0x94, 0x7B, 0x39, 0x16, 0xCF,
    0x70, 0x80, 0x1F, 0x2E, 0x28, 0x58, 0xEF, 0xC1,
    0x66, 0x36, 0x92, 0x0D, 0x87, 0x15, 0x74, 0xE6,
    0x9A, 0x45, 0x8F, 0xEA, 0x3F, 0x49, 0x33, 0xD7,
    0xE0, 0xD9, 0x57, 0x48, 0xF7, 0x28, 0xEB, 0x65,
    0x87, 0x18, 0xBC, 0xD5, 0x88, 0x21, 0x54, 0xAE,
    0xE7, 0xB5, 0x4A, 0x41, 0xDC, 0x25, 0xA5, 0x9B,
    0x59, 0xC3, 0x0D, 0x53, 0x92, 0xAF, 0x26, 0x01,
    0x3C, 0x5D, 0x1B, 0x02, 0x32, 0x86, 0x08, 0x5F,
])


def _seed_bytes(seed: int, size: int) -> bytes:
    """Expand a 64-bit seed to size bytes using HMAC-SHA256."""
    if seed == 0:
        return _MEOW_DEFAULT_SEED[:size]
    seed_le = struct.pack('<Q', seed & ((1 << 64) - 1))
    result = bytearray(size)
    offset = 0
    counter = 0
    while offset < size:
        h = hashlib.sha256(seed_le + struct.pack('<I', counter)).digest()
        copy_len = min(32, size - offset)
        result[offset:offset + copy_len] = h[:copy_len]
        offset += 32
        counter += 1
    return bytes(result)


# ---------------------------------------------------------------------------
# Meow1 — 64-bit hash (8 xmm registers)
# ---------------------------------------------------------------------------

def _meow1_mix(xmm: list[list[int]], block: bytes) -> list[list[int]]:
    """Absorb one 128-byte block into Meow1 state (8 registers)."""
    x0, x1, x2, x3, x4, x5, x6, x7 = xmm
    for off in range(0, 128, 32):
        c0 = _load16(block[off:off + 16])
        c1 = _load16(block[off + 16:off + 32])
        nx0 = _aesenc(x0, c0, x2)
        nx4 = _aesenc(x4, c1, x6)
        x0, x1, x2, x3, x4, x5, x6, x7 = x1, x2, x3, nx0, x5, x6, x7, nx4
    return [x0, x1, x2, x3, x4, x5, x6, x7]


def _meow_shuffle1(xmm: list[list[int]]) -> list[list[int]]:
    """MEOW_SHUFFLE1: 4 rounds of (aesdec + paddq + pxor) for Meow1."""
    x0, x1, x2, x3, x4, x5, x6, x7 = xmm
    for _ in range(4):
        t = x0
        x1 = _add_u64(x1, x5)
        x4 = _aesdec(x4, x6)
        x5 = _add_u64(x5, x6)
        x1 = _aesdec(x1, x2)
        x6 = _xor_state(x6, x7)
        x2 = _xor_state(x2, x3)
        x0, x1, x2, x3, x4, x5, x6, x7 = x1, x2, x3, x4, x5, x6, x7, t
    return [x0, x1, x2, x3, x4, x5, x6, x7]


def _meow1_hash_raw(data: bytes, seed_bytes: bytes) -> int:
    """Core Meow1 — seed_bytes must be 128 bytes."""
    xmm = [_load16(seed_bytes[i:i + 16]) for i in range(0, 128, 16)]
    n = len(data) // 128
    for i in range(n):
        xmm = _meow1_mix(xmm, data[i * 128:(i + 1) * 128])
    rem = len(data) % 128
    if rem > 0:
        blk = bytearray(128)
        blk[:rem] = data[n * 128:]
        xmm = _meow1_mix(xmm, bytes(blk))
    # Finalize: zero-pad residual, append 64-bit little-endian length
    fin = bytearray(128)
    struct.pack_into('<Q', fin, 0, len(data) & ((1 << 64) - 1))
    xmm = _meow1_mix(xmm, bytes(fin))
    xmm = _meow_shuffle1(xmm)
    xmm = _meow_shuffle1(xmm)
    lo = (int.from_bytes(bytes(xmm[0][:8]), 'little') +
           int.from_bytes(bytes(xmm[1][:8]), 'little') +
           int.from_bytes(bytes(xmm[4][:8]), 'little') +
           int.from_bytes(bytes(xmm[6][:8]), 'little')) & ((1 << 64) - 1)
    return lo


# ---------------------------------------------------------------------------
# Meow2 — 128-bit hash (11 xmm registers)
# ---------------------------------------------------------------------------

def _meow2_mix(xmm: list[list[int]], block: bytes) -> list[list[int]]:
    """Absorb one 128-byte block into Meow2 state (11 registers)."""
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = xmm
    for off in range(0, 128, 32):
        c0 = _load16(block[off:off + 16])
        c1 = _load16(block[off + 16:off + 32])
        nx0 = _aesenc(x0, c0, x4)
        nx4 = _aesenc(x4, c1, x8)
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = (
            x1, x2, x3, nx0, x5, x6, x7, x8, x9, x10, nx4)
    return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10]


def _meow_shuffle2(xmm: list[list[int]]) -> list[list[int]]:
    """MEOW_SHUFFLE2: 4 rounds of (aesdec + paddq + pxor) for Meow2."""
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = xmm
    for _ in range(4):
        t = x0
        x1 = _add_u64(x1, x9)
        x0 = _aesdec(x0, x8)
        x4 = _aesdec(x4, x1)
        x8 = _add_u64(x8, x10)
        x1 = _aesdec(x1, x2)
        x9 = _aesdec(x9, x5)
        x2 = _xor_state(x2, x3)
        x5 = _xor_state(x5, x6)
        x10 = _xor_state(x10, x0)
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = (
            x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, t)
    return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10]


def _meow2_hash_raw(data: bytes, seed_bytes: bytes) -> Tuple[int, int]:
    """Core Meow2 — seed_bytes must be 176 bytes. Returns (lo, hi)."""
    xmm = [_load16(seed_bytes[i:i + 16]) for i in range(0, 176, 16)][:11]
    n = len(data) // 128
    for i in range(n):
        xmm = _meow2_mix(xmm, data[i * 128:(i + 1) * 128])
    rem = len(data) % 128
    if rem > 0:
        blk = bytearray(128)
        blk[:rem] = data[n * 128:]
        xmm = _meow2_mix(xmm, bytes(blk))
    fin = bytearray(128)
    struct.pack_into('<Q', fin, 0, len(data) & ((1 << 64) - 1))
    xmm = _meow2_mix(xmm, bytes(fin))
    for _ in range(4):
        xmm = _meow_shuffle2(xmm)
    lo = (int.from_bytes(bytes(xmm[0][:8]), 'little') +
           int.from_bytes(bytes(xmm[1][:8]), 'little') +
           int.from_bytes(bytes(xmm[4][:8]), 'little') +
           int.from_bytes(bytes(xmm[6][:8]), 'little')) & ((1 << 64) - 1)
    hi = (int.from_bytes(bytes(xmm[0][8:16]), 'little') +
           int.from_bytes(bytes(xmm[1][8:16]), 'little') +
           int.from_bytes(bytes(xmm[4][8:16]), 'little') +
           int.from_bytes(bytes(xmm[5][8:16]), 'little') +
           int.from_bytes(bytes(xmm[7][8:16]), 'little')) & ((1 << 64) - 1)
    return lo, hi


# ---------------------------------------------------------------------------
# Seed expansion (public API)
# ---------------------------------------------------------------------------

def expand_seed(key: bytes) -> bytes:
    """Expand arbitrary key bytes into a 128-byte seed schedule.

    Raises:
        MeowHashError: If key is not bytes.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise MeowHashError(f"expand_seed requires bytes, got {type(key).__name__}")
    if not key:
        return _MEOW_DEFAULT_SEED[:128]
    data = struct.pack('<Q', len(key)) + key * ((256 // len(key)) + 2)
    lo, _ = _meow2_hash_raw(data, _MEOW_DEFAULT_SEED)
    result = bytearray(128)
    struct.pack_into('<Q', result, 0, lo)
    for i in range(16, 128, 16):
        h = _meow2_hash_raw(key + struct.pack('<I', i), _MEOW_DEFAULT_SEED)
        struct.pack_into('<Q', result, i, h[0] ^ h[1])
    return bytes(result)


# ---------------------------------------------------------------------------
# Public API — total over arbitrary input (Invariant 21)
# ---------------------------------------------------------------------------

def meow64(data: bytes, seed: int = 0) -> int:
    """Return 64-bit MeowHash digest as Python int [0, 2**64)."""
    try:
        if not isinstance(data, (bytes, bytearray)):
            raise MeowHashError(f"meow64 requires bytes, got {type(data).__name__}")
        if not isinstance(seed, int):
            raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64:
            raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 128)
        return _meow1_hash_raw(bytes(data), sb)
    except MeowHashError:
        raise
    except Exception as e:
        raise MeowHashError(f"meow64: {e}") from e


def meow128(data: bytes, seed: int = 0) -> Tuple[int, int]:
    """Return 128-bit MeowHash digest as (lo, hi) tuple."""
    try:
        if not isinstance(data, (bytes, bytearray)):
            raise MeowHashError(f"meow128 requires bytes, got {type(data).__name__}")
        if not isinstance(seed, int):
            raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64:
            raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 176)
        return _meow2_hash_raw(bytes(data), sb)
    except MeowHashError:
        raise
    except Exception as e:
        raise MeowHashError(f"meow128: {e}") from e


class State128:
    """Streaming 128-bit hash state. Uses Meow1 internally for 64-bit output.

    finalize() returns the same value as meow64(concatenated_chunks, seed=seed).
    """

    __slots__ = ('_xmm', '_buffer', '_buffer_len', '_total', '_finalized')

    def __init__(self, seed: int = 0) -> None:
        if not isinstance(seed, int):
            raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64:
            raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 128)
        self._xmm = [_load16(sb[i:i + 16]) for i in range(0, 128, 16)]
        self._buffer = bytearray(128)
        self._buffer_len = 0
        self._total = 0
        self._finalized = False

    def absorb(self, chunk: bytes) -> None:
        if self._finalized:
            raise MeowHashError("absorb called after finalize")
        if not isinstance(chunk, (bytes, bytearray)):
            raise MeowHashError(f"absorb requires bytes, got {type(chunk).__name__}")
        if not chunk:
            return
        self._total += len(chunk)
        data = bytes(chunk)
        if self._buffer_len > 0:
            fill = min(len(data), 128 - self._buffer_len)
            self._buffer[self._buffer_len:self._buffer_len + fill] = data[:fill]
            self._buffer_len += fill
            if self._buffer_len == 128:
                self._xmm = _meow1_mix(self._xmm, bytes(self._buffer))
                self._buffer_len = 0
            data = data[fill:]
            if not data:
                return
        while len(data) >= 128:
            self._xmm = _meow1_mix(self._xmm, data[:128])
            data = data[128:]
        if data:
            self._buffer[:len(data)] = data
            self._buffer_len = len(data)

    def finalize(self) -> int:
        if self._finalized:
            raise MeowHashError("finalize called twice")
        self._finalized = True
        try:
            if self._buffer_len > 0:
                blk = bytearray(128)
                blk[:self._buffer_len] = self._buffer[:self._buffer_len]
                self._xmm = _meow1_mix(self._xmm, bytes(blk))
                self._buffer_len = 0
            fin = bytearray(128)
            struct.pack_into('<Q', fin, 0, self._total & ((1 << 64) - 1))
            self._xmm = _meow1_mix(self._xmm, bytes(fin))
            self._xmm = _meow_shuffle1(self._xmm)
            self._xmm = _meow_shuffle1(self._xmm)
            return (int.from_bytes(bytes(self._xmm[0][:8]), 'little') +
                    int.from_bytes(bytes(self._xmm[1][:8]), 'little') +
                    int.from_bytes(bytes(self._xmm[4][:8]), 'little') +
                    int.from_bytes(bytes(self._xmm[6][:8]), 'little')) & ((1 << 64) - 1)
        except Exception as e:
            raise MeowHashError(f"finalize: {e}") from e
