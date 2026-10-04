from __future__ import annotations
import hashlib, struct
from typing import Tuple
__all__ = ['meow64', 'meow128', 'State128', 'expand_seed', 'MeowHashError']
class MeowHashError(Exception): pass
_AES_SBOX = bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
_ISBOX = bytes([i for _, i in sorted((v, k) for k, v in enumerate(_AES_SBOX))])
def _aesenc(a, b, rk):
    s = [_AES_SBOX[a[i] ^ b[i]] for i in range(16)]
    s = [s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]
    for i in range(0, 16, 4):
        c0, c1, c2, c3 = s[i], s[i+1], s[i+2], s[i+3]
        s[i]=(0x02*c0^0x03*c1^c2^c3)&0xff; s[i+1]=(c0^0x02*c1^0x03*c2^c3)&0xff
        s[i+2]=(c0^c1^0x02*c2^0x03*c3)&0xff; s[i+3]=(0x03*c0^c1^c2^0x02*c3)&0xff
    return [s[i] ^ rk[i] for i in range(16)]
def _aesdec(a, rk):
    s = [_ISBOX[a[i] ^ rk[i]] for i in range(16)]
    return [s[0],s[13],s[10],s[7],s[4],s[1],s[14],s[11],s[8],s[5],s[2],s[15],s[12],s[9],s[6],s[3]]
def _xor(a, b): return [a[i] ^ b[i] for i in range(16)]
def _l16(d): return list(d[:16])
def _add64(a, b):
    def u(x, o=0): return int.from_bytes(bytes(x[o:o+8]), 'little')
    return list(int.to_bytes((u(a)+u(b))&((1<<64)-1), 8, 'little')) + list(int.to_bytes((u(a,8)+u(b,8))&((1<<64)-1), 8, 'little'))
_MEOW_DEFAULT_SEED = bytes([0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34,0x4A,0x40,0x93,0x82,0x22,0x99,0xF3,0x1D,0x00,0x82,0xEF,0xA9,0x8E,0xC4,0xE6,0xC8,0x94,0x52,0x82,0x1E,0x63,0x8D,0x01,0x37,0x7B,0xE5,0x46,0x6C,0xF3,0x4E,0x90,0xC6,0xCC,0x0A,0xC2,0x9B,0x7C,0x97,0xC5,0x0D,0xD3,0xF8,0x4D,0x5B,0x5B,0x54,0x70,0x91,0x79,0x21,0x6D,0x5D,0x98,0x97,0x9F,0xB1,0xBD,0x13,0x10,0xBA,0x69,0x8D,0xFB,0x5A,0xC2,0xFF,0xD7,0x2D,0xBD,0x01,0xAD,0xFB,0x7B,0x8E,0x1A,0xFE,0xD6,0xA2,0x67,0xE9,0x6B,0xA7,0xC9,0x04,0x5F,0x12,0xC7,0xF9,0x92,0x4A,0x19,0x94,0x7B,0x39,0x16,0xCF,0x70,0x80,0x1F,0x2E,0x28,0x58,0xEF,0xC1,0x66,0x36,0x92,0x0D,0x87,0x15,0x74,0xE6,0x9A,0x45,0x8F,0xEA,0x3F,0x49,0x33,0xD7,0xE0,0xD9,0x57,0x48,0xF7,0x28,0xEB,0x65,0x87,0x18,0xBC,0xD5,0x88,0x21,0x54,0xAE,0xE7,0xB5,0x4A,0x41,0xDC,0x25,0xA5,0x9B,0x59,0xC3,0x0D,0x53,0x92,0xAF,0x26,0x01,0x3C,0x5D,0x1B,0x02,0x32,0x86,0x08,0x5F])
def _seed_bytes(seed, size):
    if seed == 0: return _MEOW_DEFAULT_SEED[:size]
    sb = struct.pack('<Q', seed & ((1 << 64) - 1))
    r = bytearray(size)
    for off in range(0, size, 32):
        h = hashlib.sha256(sb + struct.pack('<I', off // 32)).digest()
        r[off:off+32] = h
    return bytes(r)
def _meow1_mix(xmm, block):
    x0, x1, x2, x3, x4, x5, x6, x7 = xmm
    for off in range(0, 128, 32):
        c0 = _l16(block[off:off+16]); c1 = _l16(block[off+16:off+32])
        nx0 = _aesenc(x0, c0, x2); nx4 = _aesenc(x4, c1, x6)
        x0, x1, x2, x3, x4, x5, x6, x7 = x1, x2, x3, nx0, x5, x6, x7, nx4
    return [x0, x1, x2, x3, x4, x5, x6, x7]
def _meow_shuffle1(xmm):
    x0, x1, x2, x3, x4, x5, x6, x7 = xmm
    for _ in range(4):
        t = x0; x1 = _add64(x1, x5); x4 = _aesdec(x4, x6); x5 = _add64(x5, x6)
        x1 = _aesdec(x1, x2); x6 = _xor(x6, x7); x2 = _xor(x2, x3)
        x0, x1, x2, x3, x4, x5, x6, x7 = x1, x2, x3, x4, x5, x6, x7, t
    return [x0, x1, x2, x3, x4, x5, x6, x7]
def _meow1_hash_raw(data, seed_bytes):
    xmm = [_l16(seed_bytes[i:i+16]) for i in range(0, 128, 16)]
    n = len(data) // 128
    for i in range(n): xmm = _meow1_mix(xmm, data[i*128:(i+1)*128])
    rem = len(data) % 128
    if rem > 0:
        blk = bytearray(128); blk[:rem] = data[n*128:]; xmm = _meow1_mix(xmm, bytes(blk))
    fin = bytearray(128); struct.pack_into('<Q', fin, 0, len(data) & ((1<<64)-1))
    xmm = _meow1_mix(xmm, bytes(fin)); xmm = _meow_shuffle1(xmm); xmm = _meow_shuffle1(xmm)
    lo = (int.from_bytes(bytes(xmm[0][:8]), 'little') + int.from_bytes(bytes(xmm[1][:8]), 'little') +
          int.from_bytes(bytes(xmm[4][:8]), 'little') + int.from_bytes(bytes(xmm[6][:8]), 'little')) & ((1<<64)-1)
    return lo
def _meow2_mix(xmm, block):
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = xmm
    for off in range(0, 128, 32):
        c0 = _l16(block[off:off+16]); c1 = _l16(block[off+16:off+32])
        nx0 = _aesenc(x0, c0, x4); nx4 = _aesenc(x4, c1, x8)
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = x1, x2, x3, nx0, x5, x6, x7, x8, x9, x10, nx4
    return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10]
def _meow_shuffle2(xmm):
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = xmm
    for _ in range(4):
        t = x0; x1 = _add64(x1, x9); x0 = _aesdec(x0, x8); x4 = _aesdec(x4, x1)
        x8 = _add64(x8, x10); x1 = _aesdec(x1, x2); x9 = _aesdec(x9, x5)
        x2 = _xor(x2, x3); x5 = _xor(x5, x6); x10 = _xor(x10, x0)
        x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, t
    return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10]
def _meow2_hash_raw(data, seed_bytes):
    xmm = [_l16(seed_bytes[i:i+16]) for i in range(0, 176, 16)][:11]
    n = len(data) // 128
    for i in range(n): xmm = _meow2_mix(xmm, data[i*128:(i+1)*128])
    rem = len(data) % 128
    if rem > 0:
        blk = bytearray(128); blk[:rem] = data[n*128:]; xmm = _meow2_mix(xmm, bytes(blk))
    fin = bytearray(128); struct.pack_into('<Q', fin, 0, len(data) & ((1<<64)-1))
    xmm = _meow2_mix(xmm, bytes(fin))
    for _ in range(4): xmm = _meow_shuffle2(xmm)
    lo = (int.from_bytes(bytes(xmm[0][:8]), 'little') + int.from_bytes(bytes(xmm[1][:8]), 'little') +
          int.from_bytes(bytes(xmm[4][:8]), 'little') + int.from_bytes(bytes(xmm[6][:8]), 'little')) & ((1<<64)-1)
    hi = (int.from_bytes(bytes(xmm[0][8:16]), 'little') + int.from_bytes(bytes(xmm[1][8:16]), 'little') +
          int.from_bytes(bytes(xmm[4][8:16]), 'little') + int.from_bytes(bytes(xmm[5][8:16]), 'little') +
          int.from_bytes(bytes(xmm[7][8:16]), 'little')) & ((1<<64)-1)
    return lo, hi
def expand_seed(key):
    if not isinstance(key, (bytes, bytearray)): raise MeowHashError(f"expand_seed requires bytes, got {type(key).__name__}")
    if not key: return _MEOW_DEFAULT_SEED[:128]
    data = struct.pack('<Q', len(key)) + key * ((256 // len(key)) + 2)
    lo, _ = _meow2_hash_raw(data, _MEOW_DEFAULT_SEED)
    result = bytearray(128); struct.pack_into('<Q', result, 0, lo)
    for i in range(16, 128, 16):
        h = _meow2_hash_raw(key + struct.pack('<I', i), _MEOW_DEFAULT_SEED)
        struct.pack_into('<Q', result, i, h[0] ^ h[1])
    return bytes(result)
def meow64(data, seed=0):
    try:
        if not isinstance(data, (bytes, bytearray)): raise MeowHashError(f"meow64 requires bytes, got {type(data).__name__}")
        if not isinstance(seed, int): raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64: raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 128); return _meow1_hash_raw(bytes(data), sb)
    except MeowHashError: raise
    except Exception as e: raise MeowHashError(f"meow64: {e}") from e
def meow128(data, seed=0):
    try:
        if not isinstance(data, (bytes, bytearray)): raise MeowHashError(f"meow128 requires bytes, got {type(data).__name__}")
        if not isinstance(seed, int): raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64: raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 176); return _meow2_hash_raw(bytes(data), sb)
    except MeowHashError: raise
    except Exception as e: raise MeowHashError(f"meow128: {e}") from e
class State128:
    __slots__ = ('_xmm', '_buffer', '_buffer_len', '_total', '_finalized')
    def __init__(self, seed=0):
        if not isinstance(seed, int): raise MeowHashError(f"seed must be int, got {type(seed).__name__}")
        if seed < 0 or seed >= 2**64: raise MeowHashError(f"seed must be in [0, 2**64), got {seed}")
        sb = _seed_bytes(seed, 128)
        self._xmm = [_l16(sb[i:i+16]) for i in range(0, 128, 16)]
        self._buffer = bytearray(128); self._buffer_len = 0; self._total = 0; self._finalized = False
    def absorb(self, chunk):
        if self._finalized: raise MeowHashError("absorb called after finalize")
        if not isinstance(chunk, (bytes, bytearray)): raise MeowHashError(f"absorb requires bytes, got {type(chunk).__name__}")
        if not chunk: return
        self._total += len(chunk); data = bytes(chunk)
        if self._buffer_len > 0:
            fill = min(len(data), 128 - self._buffer_len)
            self._buffer[self._buffer_len:self._buffer_len + fill] = data[:fill]; self._buffer_len += fill
            if self._buffer_len == 128: self._xmm = _meow1_mix(self._xmm, bytes(self._buffer)); self._buffer_len = 0
            data = data[fill:]
            if not data: return
        while len(data) >= 128: self._xmm = _meow1_mix(self._xmm, data[:128]); data = data[128:]
        if data: self._buffer[:len(data)] = data; self._buffer_len = len(data)
    def finalize(self):
        if self._finalized: raise MeowHashError("finalize called twice")
        self._finalized = True
        try:
            if self._buffer_len > 0:
                blk = bytearray(128); blk[:self._buffer_len] = self._buffer[:self._buffer_len]
                self._xmm = _meow1_mix(self._xmm, bytes(blk)); self._buffer_len = 0
            fin = bytearray(128); struct.pack_into('<Q', fin, 0, self._total & ((1<<64)-1))
            self._xmm = _meow1_mix(self._xmm, bytes(fin)); self._xmm = _meow_shuffle1(self._xmm); self._xmm = _meow_shuffle1(self._xmm)
            return (int.from_bytes(bytes(self._xmm[0][:8]), 'little') + int.from_bytes(bytes(self._xmm[1][:8]), 'little') +
                    int.from_bytes(bytes(self._xmm[4][:8]), 'little') + int.from_bytes(bytes(self._xmm[6][:8]), 'little')) & ((1<<64)-1)
        except Exception as e: raise MeowHashError(f"finalize: {e}") from e
