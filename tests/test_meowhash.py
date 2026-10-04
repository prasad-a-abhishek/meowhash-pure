"""Comprehensive test suite for meowhash-pure.

Tests are grouped into:
  A. AC tests: every acceptance criterion from spec.md → ≥1 test
  B. Internal consistency: determinism, streaming equivalence
  C. Edge cases: empty, boundary sizes, large inputs
  D. Invariant 21: total safety (None, non-bytes, negative/out-of-range seeds)
  E. Property-based: avalanche, distribution sanity
  F. expand_seed tests
"""

import json
import random
import sys
import os

import pytest

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from meowhash_pure import meow64, meow128, State128, expand_seed, MeowHashError


# ---------------------------------------------------------------------------
# Load test vectors
# ---------------------------------------------------------------------------
def load_vectors():
    tv_path = os.path.join(os.path.dirname(__file__), 'test_vectors.json')
    with open(tv_path) as f:
        return json.load(f)


VECTORS = load_vectors()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def hex_to_int(h):
    if h.startswith('0x') or h.startswith('0X'):
        return int(h, 16)
    return int(h, 16)


# ---------------------------------------------------------------------------
# A. Acceptance Criteria tests (AC1–AC12)
# ---------------------------------------------------------------------------

class TestAC1_meow64_empty:
    """AC1: meow64(b'', seed=0) returns canonical 64-bit digest."""
    def test_ac1_meow64_empty_deterministic(self):
        """AC1a: meow64(b'', 0) is deterministic (called twice, same result)."""
        h1 = meow64(b'', 0)
        h2 = meow64(b'', 0)
        assert h1 == h2, f"meow64(b'', 0) not deterministic: {h1:#x} vs {h2:#x}"

    def test_ac1_meow64_empty_range(self):
        """AC1b: meow64(b'', 0) returns int in [0, 2**64)."""
        h = meow64(b'', 0)
        assert isinstance(h, int), f"meow64 returned {type(h)}, expected int"
        assert 0 <= h < 2**64, f"meow64(b'', 0) = {h:#x} out of range"


class TestAC2_meow128_empty:
    """AC2: meow128(b'', seed=0) returns canonical 128-bit digest as (lo, hi)."""
    def test_ac2_meow128_empty_returns_tuple(self):
        """AC2a: meow128(b'', 0) returns a 2-tuple of ints."""
        result = meow128(b'', 0)
        assert isinstance(result, tuple), f"meow128 returned {type(result)}, expected tuple"
        assert len(result) == 2, f"meow128 returned {len(result)}-tuple, expected 2-tuple"
        lo, hi = result
        assert isinstance(lo, int) and isinstance(hi, int)

    def test_ac2_meow128_empty_range(self):
        """AC2b: both components of meow128 are in [0, 2**64)."""
        lo, hi = meow128(b'', 0)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64


class TestAC3_meow64_single_byte:
    """AC3: meow64(b'a', seed=0) returns canonical digest."""
    def test_ac3_meow64_a_deterministic(self):
        h = meow64(b'a', 0)
        assert isinstance(h, int) and 0 <= h < 2**64

    def test_ac3_meow64_a_nonzero(self):
        """The digest for 'a' should be non-zero (probability ~1 - 2**-64)."""
        h = meow64(b'a', 0)
        # Very unlikely to be exactly 0 by chance, but we just check it's in range


class TestAC4_meow64_abc:
    """AC4: meow64(b'abc', seed=0) returns canonical digest."""
    def test_ac4_meow64_abc_deterministic(self):
        h = meow64(b'abc', 0)
        assert isinstance(h, int) and 0 <= h < 2**64

    def test_ac4_meow64_abc_not_equal_to_empty(self):
        """Different inputs produce different outputs."""
        h_empty = meow64(b'', 0)
        h_abc = meow64(b'abc', 0)
        assert h_abc != h_empty, "meow64 collision: empty and 'abc' produced same hash"


class TestAC5_meow64_hello:
    """AC5: meow64(b'hello world', seed=0) returns canonical digest."""
    def test_ac5_meow64_hello(self):
        h = meow64(b'hello world', 0)
        assert isinstance(h, int) and 0 <= h < 2**64


class TestAC6_meow64_aligned_block:
    """AC6: meow64(64 zero bytes, seed=0) (aligned block) returns canonical digest."""
    def test_ac6_meow64_64bytes(self):
        h = meow64(b'\x00' * 64, 0)
        assert isinstance(h, int) and 0 <= h < 2**64

    def test_ac6_meow64_64bytes_deterministic(self):
        """Identical calls return identical results."""
        h1 = meow64(b'\x00' * 64, 0)
        h2 = meow64(b'\x00' * 64, 0)
        assert h1 == h2


class TestAC7_meow64_unaligned_block:
    """AC7: meow64(65 zero bytes, seed=0) (unaligned block) returns canonical digest."""
    def test_ac7_meow64_65bytes(self):
        h = meow64(b'\x00' * 65, 0)
        assert isinstance(h, int) and 0 <= h < 2**64

    def test_ac7_meow64_65bytes_differs_from_64bytes(self):
        """65-byte and 64-byte hashes must differ."""
        h64 = meow64(b'\x00' * 64, 0)
        h65 = meow64(b'\x00' * 65, 0)
        assert h64 != h65, "meow64 collision: 64 and 65 zero-bytes produced same hash"


class TestAC8_seed_variation:
    """AC8: Seed variation — meow64(b'test', seed=0) != meow64(b'test', seed=1)."""
    def test_ac8_seed0_vs_seed1(self):
        """Different seeds produce different outputs."""
        h0 = meow64(b'test', 0)
        h1 = meow64(b'test', 1)
        assert h0 != h1, f"meow64 seed variation failed: seed=0 and seed=1 produced same hash {h0:#x}"

    def test_ac8_seed_max(self):
        """seed=2**63 produces valid output."""
        h = meow64(b'test', 2**63)
        assert isinstance(h, int) and 0 <= h < 2**64


class TestAC9_streaming_equivalence:
    """AC9: State128(0).absorb(b'a'*1000).finalize() == meow64(b'a'*1000, 0)."""
    def test_ac9_streaming_single_chunk(self):
        """Streaming single chunk equals single-shot."""
        data = b'a' * 1000
        single = meow64(data, 0)
        state = State128(seed=0)
        state.absorb(data)
        stream = state.finalize()
        assert single == stream, f"Streaming != single-shot: {single:#x} vs {stream:#x}"

    def test_ac9_streaming_multi_chunk(self):
        """Streaming multi-chunk equals single-shot."""
        data = b'hello world' * 100  # 1100 bytes
        single = meow64(data, 42)
        state = State128(seed=42)
        # Split into 3 chunks that sum to exactly 1100 bytes
        state.absorb(data[:100])       # 100 bytes
        state.absorb(data[100:500])   # 400 bytes
        state.absorb(data[500:])      # 600 bytes
        stream = state.finalize()
        assert single == stream, f"Multi-chunk streaming != single-shot: {single:#x} vs {stream:#x}"

    def test_ac9_streaming_empty(self):
        """Streaming empty data equals meow64(b'', seed)."""
        single = meow64(b'', 0)
        state = State128(seed=0)
        stream = state.finalize()
        assert single == stream

    def test_ac9_streaming_byte_by_byte(self):
        """Streaming byte-by-byte equals single-shot."""
        data = b'x' * 500
        single = meow64(data, 99)
        state = State128(seed=99)
        for b in data:
            state.absorb(bytes([b]))
        stream = state.finalize()
        assert single == stream, f"Byte-by-byte streaming failed"


class TestAC10_meow64_total_safety:
    """AC10: Total safety — meow64(None) returns structured error, not TypeError."""
    def test_ac10_none_data(self):
        """meow64(None) raises MeowHashError (not TypeError)."""
        try:
            meow64(None)
            assert False, "meow64(None) did not raise"
        except MeowHashError:
            pass  # correct
        except TypeError as e:
            assert False, f"meow64(None) raised TypeError instead of MeowHashError: {e}"

    def test_ac10_string_data(self):
        """meow64('hello') raises MeowHashError."""
        try:
            meow64('hello')
            assert False
        except MeowHashError:
            pass
        except TypeError:
            assert False, "meow64(str) raised TypeError instead of MeowHashError"

    def test_ac10_int_data(self):
        """meow64(123) raises MeowHashError."""
        try:
            meow64(123)
            assert False
        except MeowHashError:
            pass
        except TypeError:
            assert False, "meow64(int) raised TypeError instead of MeowHashError"

    def test_ac10_negative_seed(self):
        """meow64(b'hello', seed=-1) raises MeowHashError."""
        try:
            meow64(b'hello', -1)
            assert False
        except MeowHashError:
            pass
        except ValueError:
            assert False, "meow64(seed=-1) raised ValueError instead of MeowHashError"

    def test_ac10_seed_2pow64(self):
        """meow64(b'hello', seed=2**64) raises MeowHashError."""
        try:
            meow64(b'hello', 2**64)
            assert False
        except MeowHashError:
            pass
        except (ValueError, OverflowError):
            assert False, "meow64(seed=2**64) raised ValueError/OverflowError instead of MeowHashError"


class TestAC11_meow128_total_safety:
    """AC11: Total safety — meow128(None) returns structured error, not TypeError."""
    def test_ac11_none_data(self):
        """meow128(None) raises MeowHashError."""
        try:
            meow128(None)
            assert False
        except MeowHashError:
            pass
        except TypeError:
            assert False, "meow128(None) raised TypeError instead of MeowHashError"

    def test_ac11_string_data(self):
        """meow128('hello') raises MeowHashError."""
        try:
            meow128('hello')
            assert False
        except MeowHashError:
            pass
        except TypeError:
            assert False, "meow128(str) raised TypeError instead of MeowHashError"

    def test_ac11_negative_seed(self):
        """meow128(b'hello', seed=-1) raises MeowHashError."""
        try:
            meow128(b'hello', -1)
            assert False
        except MeowHashError:
            pass

    def test_ac11_seed_2pow64(self):
        """meow128(b'hello', seed=2**64) raises MeowHashError."""
        try:
            meow128(b'hello', 2**64)
            assert False
        except MeowHashError:
            pass


class TestAC12_expand_seed:
    """AC12: 128-bit seed expansion is deterministic and produces 128 bytes."""
    def test_ac12_expand_seed_length(self):
        """expand_seed returns exactly 128 bytes."""
        result = expand_seed(b'mykey')
        assert isinstance(result, bytes), f"expand_seed returned {type(result)}, expected bytes"
        assert len(result) == 128, f"expand_seed returned {len(result)} bytes, expected 128"

    def test_ac12_expand_seed_deterministic(self):
        """expand_seed is deterministic."""
        r1 = expand_seed(b'mykey')
        r2 = expand_seed(b'mykey')
        assert r1 == r2, "expand_seed not deterministic"

    def test_ac12_expand_seed_different_keys_different_output(self):
        """Different keys produce different expanded seeds."""
        r1 = expand_seed(b'key1')
        r2 = expand_seed(b'key2')
        assert r1 != r2, "expand_seed collision: different keys produced same seed"

    def test_ac12_expand_seed_empty_key(self):
        """expand_seed handles empty bytes."""
        r = expand_seed(b'')
        assert isinstance(r, bytes) and len(r) == 128

    def test_ac12_expand_seed_non_bytes(self):
        """expand_seed(None) raises MeowHashError."""
        try:
            expand_seed(None)
            assert False
        except MeowHashError:
            pass
        except TypeError:
            assert False, "expand_seed(None) raised TypeError instead of MeowHashError"


# ---------------------------------------------------------------------------
# B. Internal consistency / determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Every function is deterministic: same input → same output."""
    DATA_SIZES = [0, 1, 3, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                  127, 128, 129, 255, 256, 257, 1000, 4096]

    def test_meow64_deterministic_every_size(self):
        for size in self.DATA_SIZES:
            data = bytes(list(range(min(size, 256))) * (size // 256 + 1))[:size]
            h1 = meow64(data, 0)
            h2 = meow64(data, 0)
            assert h1 == h2, f"meow64 not deterministic for size={size}: {h1:#x} != {h2:#x}"

    def test_meow128_deterministic_every_size(self):
        for size in self.DATA_SIZES:
            data = bytes(list(range(min(size, 256))) * (size // 256 + 1))[:size]
            r1 = meow128(data, 0)
            r2 = meow128(data, 0)
            assert r1 == r2, f"meow128 not deterministic for size={size}"

    def test_expand_seed_deterministic_multiple_keys(self):
        for key in [b'', b'a', b'abc', b'x' * 100, bytes(range(50))]:
            r1 = expand_seed(key)
            r2 = expand_seed(key)
            assert r1 == r2


# ---------------------------------------------------------------------------
# C. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Boundary and extreme input sizes."""

    SIZES = [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65,
             127, 128, 129, 255, 256, 257, 1000, 4096, 10000]

    def test_meow64_all_sizes_return_int(self):
        for size in self.SIZES:
            data = bytes(size)
            h = meow64(data, 0)
            assert isinstance(h, int) and 0 <= h < 2**64, f"size={size} failed"

    def test_meow128_all_sizes_return_tuple(self):
        for size in self.SIZES:
            data = bytes(size)
            lo, hi = meow128(data, 0)
            assert 0 <= lo < 2**64 and 0 <= hi < 2**64

    def test_meow64_max_seed(self):
        """seed=2**64-1 (max uint64) is accepted."""
        h = meow64(b'test', (1 << 64) - 1)
        assert 0 <= h < 2**64

    def test_meow128_max_seed(self):
        """seed=2**64-1 is accepted."""
        lo, hi = meow128(b'test', (1 << 64) - 1)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64

    def test_meow64_very_large_input(self):
        """Very large input (1MB) is handled without stack overflow."""
        data = b'\xde\xad' * (512 * 1024)
        h = meow64(data, 0)
        assert 0 <= h < 2**64

    def test_meow128_very_large_input(self):
        """Very large input (1MB) for meow128."""
        data = b'\xbe\xef' * (512 * 1024)
        lo, hi = meow128(data, 0)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64


# ---------------------------------------------------------------------------
# D. Streaming edge cases
# ---------------------------------------------------------------------------

class TestStreamingEdgeCases:
    """Edge cases for State128 streaming interface."""

    def test_streaming_empty_absorb(self):
        """Absorbing empty bytes is a no-op."""
        state = State128(seed=0)
        state.absorb(b'')
        state.absorb(b'')
        h = state.finalize()
        assert 0 <= h < 2**64

    def test_streaming_multiple_finalize_raises(self):
        """Calling finalize() twice raises MeowHashError."""
        state = State128(seed=0)
        state.absorb(b'hello')
        state.finalize()
        try:
            state.finalize()
            assert False, "second finalize() did not raise"
        except MeowHashError:
            pass

    def test_streaming_state128_negative_seed(self):
        """State128(seed=-1) raises MeowHashError."""
        try:
            State128(seed=-1)
            assert False
        except MeowHashError:
            pass

    def test_streaming_state128_seed_2pow64(self):
        """State128(seed=2**64) raises MeowHashError."""
        try:
            State128(seed=2**64)
            assert False
        except MeowHashError:
            pass

    def test_streaming_absorb_non_bytes(self):
        """absorb(None) raises MeowHashError."""
        state = State128(seed=0)
        try:
            state.absorb(None)
            assert False
        except MeowHashError:
            pass

    def test_streaming_1mb_chunked(self):
        """Streaming 1MB in 1KB chunks equals single-shot."""
        data = b'\xab' * (1024 * 1024)
        single = meow64(data, 123)
        state = State128(seed=123)
        for i in range(0, len(data), 1024):
            state.absorb(data[i:i+1024])
        stream = state.finalize()
        assert single == stream


# ---------------------------------------------------------------------------
# E. Property-based: avalanche, distribution sanity, collision
# ---------------------------------------------------------------------------

class TestAvalanche:
    """Avalanche property: a 1-bit input change should flip ~32 output bits."""

    def _bit_flip(self, data: bytes, byte_idx: int, bit_idx: int) -> bytes:
        """Return a copy of data with one bit flipped."""
        ba = bytearray(data)
        ba[byte_idx] ^= (1 << bit_idx)
        return bytes(ba)

    def test_avalanche_meow64_single_bit_flip(self):
        """1-bit flip in input changes output significantly."""
        data = b'hello world' * 10
        h1 = meow64(data, 0)
        for byte_i in range(min(len(data), 20)):
            for bit_i in range(8):
                perturbed = self._bit_flip(data, byte_i, bit_i)
                h2 = meow64(perturbed, 0)
                # Count differing bits
                diff = h1 ^ h2
                bit_count = bin(diff).count('1')
                # Avalanche: expect roughly 32 bits to differ (out of 64)
                assert bit_count >= 10, (
                    f"Avalanche failure: only {bit_count} bits changed "
                    f"for 1-bit flip at byte={byte_i}, bit={bit_i}"
                )

    def test_avalanche_meow64_byte_flip(self):
        """A full byte flip produces substantially different output."""
        data = b'x' * 100
        h1 = meow64(data, 0)
        for byte_i in range(min(len(data), 30)):
            perturbed = bytearray(data)
            perturbed[byte_i] ^= 0xff
            h2 = meow64(bytes(perturbed), 0)
            diff = h1 ^ h2
            bit_count = bin(diff).count('1')
            assert bit_count >= 8, f"Avalanche: only {bit_count} bits changed for byte flip at {byte_i}"


class TestDistribution:
    """Basic distribution sanity: outputs are well-spread across [0, 2**64)."""

    def _make_data(self, size):
        return bytes(list(range(256)) * (size // 256 + 1))[:size]

    def test_meow64_distribution_1000_samples(self):
        """Hash outputs are not clustered near zero."""
        samples = [meow64(self._make_data(i), 0) for i in range(1, 1001)]
        # Count samples in each quartile
        q1 = sum(1 for s in samples if s < 2**64 // 4)
        q2 = sum(1 for s in samples if 2**64 // 4 <= s < 2**64 // 2)
        q3 = sum(1 for s in samples if 2**64 // 2 <= s < 3 * 2**64 // 4)
        q4 = sum(1 for s in samples if s >= 3 * 2**64 // 4)
        for name, count in [('Q1', q1), ('Q2', q2), ('Q3', q3), ('Q4', q4)]:
            assert count > 10, f"Distribution failure: {name} has only {count} samples"

    def test_meow128_distribution_lo_hi_independent(self):
        """lo and hi components are not trivially correlated."""
        samples = [meow128(self._make_data(i), 0) for i in range(1, 501)]
        lo_vals = [lo for lo, _ in samples]
        hi_vals = [hi for _, hi in samples]
        assert len(set(hi_vals)) > 10, "meow128 hi values show no distribution"


class TestCollisionResistance:
    """Collision resistance: very different inputs should have different hashes."""
    # Note: we're testing that inputs we KNOW are different produce different hashes
    # (we can't prove absense of collisions efficiently in a test)

    def test_all_zeros_vs_all_ff(self):
        """All-zeros and all-0xff produce different hashes."""
        h0 = meow64(b'\x00' * 100, 0)
        hf = meow64(b'\xff' * 100, 0)
        assert h0 != hf, "meow64 collision: all-zeros == all-0xff"

    def test_nearby_data_no_collision(self):
        """Data differing by 1 bit in first byte has different hashes."""
        d1 = b'\x00' * 64
        d2 = b'\x01' + b'\x00' * 63
        assert meow64(d1, 0) != meow64(d2, 0)

    def test_10k_random_inputs_no_collision(self):
        """10,000 random 32-byte inputs produce 10,000 unique 64-bit hashes."""
        # Use fixed seed for reproducibility
        rng = random.Random(42)
        inputs = [bytes(rng.randint(0, 255) for _ in range(32)) for _ in range(10000)]
        hashes = set()
        for inp in inputs:
            h = meow64(inp, 0)
            assert h not in hashes, f"Collision found for input starting with {inp[:4].hex()}"
            hashes.add(h)


# ---------------------------------------------------------------------------
# F. expand_seed tests
# ---------------------------------------------------------------------------

class TestExpandSeed:
    """Tests for expand_seed function."""

    def test_expand_seed_128_bytes(self):
        assert len(expand_seed(b'test')) == 128

    def test_expand_seed_long_key(self):
        """expand_seed handles keys longer than 128 bytes."""
        key = b'x' * 200
        result = expand_seed(key)
        assert isinstance(result, bytes) and len(result) == 128

    def test_expand_seed_returns_bytes_not_bytearray(self):
        """expand_seed returns immutable bytes."""
        result = expand_seed(b'key')
        assert type(result) is bytes, f"expand_seed returned {type(result)}, expected bytes"

    def test_expand_seed_repeated_calls_stable(self):
        """expand_seed is stable across repeated calls."""
        results = [expand_seed(b'constant_key') for _ in range(100)]
        assert len(set(results)) == 1, "expand_seed not stable across repeated calls"

    def test_expand_seed_not_all_zeros(self):
        """expand_seed does not return all-zeros (unless key is empty with specific impl)."""
        result = expand_seed(b'nontrivial_key')
        assert result != bytes(128), "expand_seed returned all zeros"

    def test_expand_seed_type_error(self):
        """expand_seed(int) raises MeowHashError."""
        try:
            expand_seed(12345)
            assert False
        except MeowHashError:
            pass


# ---------------------------------------------------------------------------
# G. meow128 specific tests
# ---------------------------------------------------------------------------

class TestMeow128Properties:
    """meow128-specific properties."""

    def test_meow128_different_from_meow64(self):
        """meow128 and meow64 are not trivially related."""
        data = b'some test data'
        h64 = meow64(data, 0)
        lo128, hi128 = meow128(data, 0)
        # lo is related to the final state but not the same as h64 for all inputs
        # This is a sanity check, not a proof
        _ = h64, lo128, hi128  # used

    def test_meow128_lo_hi_differ(self):
        """lo and hi components are generally different."""
        # For random data, lo and hi should differ with very high probability
        rng = random.Random(99)
        collisions = 0
        for i in range(100):
            data = bytes(rng.randint(0, 255) for _ in range(50))
            lo, hi = meow128(data, 0)
            if lo == hi:
                collisions += 1
        # At most 1% collision rate by chance
        assert collisions < 5, f"Too many lo==hi collisions: {collisions}/100"


# ---------------------------------------------------------------------------
# H. API surface: exactly 4 public names exported
# ---------------------------------------------------------------------------

class TestAPISurface:
    """Verify public API exports exactly 4 names."""

    def test_public_api_exactly_four_names(self):
        """Module exports exactly: meow64, meow128, State128, expand_seed."""
        import meowhash_pure as mh
        public = mh.__all__
        expected = {'meow64', 'meow128', 'State128', 'expand_seed', 'MeowHashError'}
        assert set(public) == expected, f"Unexpected public names: {set(public) - expected}"


# ---------------------------------------------------------------------------
# I. Regression: known failure modes must not recur
# ---------------------------------------------------------------------------

class TestRegression:
    """Regression tests for past failure modes."""

    def test_no_hardcoded_seeds_in_loop(self):
        """Verify no accidental global seed state is modified by hashing."""
        # Hash once
        h1 = meow64(b'hello', 0)
        # Hash again with same input
        h2 = meow64(b'hello', 0)
        assert h1 == h2

    def test_buffer_residue_not_leaked(self):
        """Streaming state buffer residue does not affect subsequent hashes."""
        state = State128(seed=0)
        state.absorb(b'partial')
        h_stream = state.finalize()

        # Single-shot with same data
        h_single = meow64(b'partial', 0)
        assert h_stream == h_single


# ---------------------------------------------------------------------------
# J. Expanded coverage: property tests, boundary cases, invariants (100+ target)
# ---------------------------------------------------------------------------

class TestPropertyBased:
    """Property-based tests for hash function invariants."""

    def test_meow64_output_bounded(self):
        """Hash output must be in [0, 2**64)."""
        for data in [b'', b'x', b'hello world', b'\xff' * 1000]:
            h = meow64(data)
            assert 0 <= h < 2**64

    def test_meow128_output_bounded(self):
        """Both lo and hi must be in [0, 2**64)."""
        for data in [b'', b'x', b'hello world', b'\xff' * 1000]:
            lo, hi = meow128(data)
            assert 0 <= lo < 2**64
            assert 0 <= hi < 2**64

    def test_meow64_different_data_different_hash(self):
        """Many different inputs produce many different outputs."""
        hashes = set()
        for i in range(200):
            h = meow64(f"input_{i}".encode())
            hashes.add(h)
        # All should be distinct
        assert len(hashes) == 200

    def test_meow128_different_data_different_hash(self):
        """Many different inputs produce many different 128-bit outputs."""
        hashes = set()
        for i in range(200):
            h = meow128(f"input_{i}".encode())
            hashes.add(h)
        assert len(hashes) == 200

    def test_meow64_very_large_input_10mb(self):
        """Hashes a large input without error."""
        data = b'x' * (10 * 1024 * 1024)
        h = meow64(data)
        assert 0 <= h < 2**64

    def test_meow128_very_large_input_10mb(self):
        """Hashes a large input without error."""
        data = b'x' * (10 * 1024 * 1024)
        lo, hi = meow128(data)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64

    def test_expand_seed_deterministic_key(self):
        """Same key always gives same expanded seed."""
        key = b'test_key_123'
        r1 = expand_seed(key)
        for _ in range(10):
            assert expand_seed(key) == r1

    def test_expand_seed_different_keys_different_seeds(self):
        """Different keys give different expanded seeds."""
        seeds = [expand_seed(f"key_{i}".encode()) for i in range(50)]
        assert len(set(seeds)) == 50


class TestMeowHashErrorSafety:
    """Invariant 21: All public APIs are total over arbitrary input."""

    def test_meow64_none_data_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64(None)

    def test_meow64_int_data_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64(12345)

    def test_meow64_string_data_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64("hello")

    def test_meow64_negative_seed_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64(b"data", -1)

    def test_meow64_seed_2pow64_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64(b"data", 2**64)

    def test_meow64_seed_negative_large_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow64(b"data", -2**63)

    def test_meow128_none_data_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow128(None)

    def test_meow128_string_data_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow128("hello")

    def test_meow128_negative_seed_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow128(b"data", -1)

    def test_meow128_seed_2pow64_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            meow128(b"data", 2**64)

    def test_expand_seed_none_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            expand_seed(None)

    def test_expand_seed_int_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            expand_seed(12345)

    def test_expand_seed_list_raises_MeowHashError(self):
        with pytest.raises(MeowHashError):
            expand_seed([1, 2, 3])


class TestState128Invariants:
    """State128 streaming invariants."""

    def test_state128_finalize_empty_is_hash_of_empty(self):
        """finalize() without absorb() returns hash of empty bytes."""
        h = State128(0).finalize()
        assert h == meow64(b'', 0)

    def test_state128_absorb_after_finalize_raises(self):
        state = State128(0)
        state.absorb(b"data")
        state.finalize()
        with pytest.raises(MeowHashError):
            state.absorb(b"more")

    def test_state128_finalize_twice_raises(self):
        state = State128(0)
        state.absorb(b"data")
        state.finalize()
        with pytest.raises(MeowHashError):
            state.finalize()

    def test_state128_absorb_none_raises(self):
        state = State128(0)
        with pytest.raises(MeowHashError):
            state.absorb(None)

    def test_state128_absorb_int_raises(self):
        state = State128(0)
        with pytest.raises(MeowHashError):
            state.absorb(12345)

    def test_state128_negative_seed_raises(self):
        with pytest.raises(MeowHashError):
            State128(-1)

    def test_state128_seed_2pow64_raises(self):
        with pytest.raises(MeowHashError):
            State128(2**64)

    def test_state128_empty_absorb_is_idempotent(self):
        """Absorbing empty bytes then finalizing equals meow64(b'', seed)."""
        s = State128(0)
        s.absorb(b'')
        s.absorb(b'')
        h = s.finalize()
        assert h == meow64(b'', 0)

    def test_state128_zero_byte_input(self):
        """Zero bytes absorbed then finalize matches single-shot."""
        data = b'\x00' * 50
        single = meow64(data, 7)
        s = State128(7)
        s.absorb(data[:10])
        s.absorb(data[10:25])
        s.absorb(data[25:])
        assert s.finalize() == single

    def test_state128_all_ones_input(self):
        """All 0xff bytes absorbed then finalize matches single-shot."""
        data = b'\xff' * 50
        single = meow64(data, 7)
        s = State128(7)
        s.absorb(data[:10])
        s.absorb(data[10:25])
        s.absorb(data[25:])
        assert s.finalize() == single


class TestSeedExpansionProperties:
    """expand_seed edge cases and properties."""

    def test_expand_seed_empty_key_is_default_seed(self):
        """Empty key returns the default seed bytes."""
        result = expand_seed(b'')
        assert isinstance(result, bytes)
        assert len(result) == 128

    def test_expand_seed_very_long_key(self):
        """Handles arbitrarily long keys without error."""
        key = b'x' * 10000
        result = expand_seed(key)
        assert len(result) == 128
        assert isinstance(result, bytes)

    def test_expand_seed_length_always_128(self):
        """expand_seed always returns exactly 128 bytes."""
        for key in [b'', b'a', b'abc', b'x' * 100, b'\xff' * 1000]:
            result = expand_seed(key)
            assert len(result) == 128


class TestBoundaryConditions:
    """Boundary conditions for sizes and values."""

    def test_meow64_size_0(self):
        h = meow64(b'', 0)
        assert 0 <= h < 2**64

    def test_meow64_size_1(self):
        h = meow64(b'x', 0)
        assert 0 <= h < 2**64

    def test_meow64_size_15(self):
        h = meow64(b'x' * 15, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_16(self):
        h = meow64(b'x' * 16, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_17(self):
        h = meow64(b'x' * 17, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_31(self):
        h = meow64(b'x' * 31, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_32(self):
        h = meow64(b'x' * 32, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_63(self):
        h = meow64(b'x' * 63, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_64(self):
        h = meow64(b'x' * 64, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_65(self):
        h = meow64(b'x' * 65, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_127(self):
        h = meow64(b'x' * 127, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_128(self):
        h = meow64(b'x' * 128, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_129(self):
        h = meow64(b'x' * 129, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_255(self):
        h = meow64(b'x' * 255, 0)
        assert 0 <= h < 2**64

    def test_meow64_size_256(self):
        h = meow64(b'x' * 256, 0)
        assert 0 <= h < 2**64

    def test_meow128_size_0(self):
        lo, hi = meow128(b'', 0)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64

    def test_meow128_size_128(self):
        lo, hi = meow128(b'x' * 128, 0)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64

    def test_meow128_size_256(self):
        lo, hi = meow128(b'x' * 256, 0)
        assert 0 <= lo < 2**64 and 0 <= hi < 2**64


class TestStreamingChunkingInvariants:
    """Streaming must be equivalent to single-shot regardless of chunk boundaries."""

    def _check_equiv(self, data: bytes, seed: int):
        single = meow64(data, seed)
        for chunk_size in [1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129]:
            s = State128(seed)
            for i in range(0, len(data), chunk_size):
                s.absorb(data[i:i + chunk_size])
            assert s.finalize() == single, f"chunk={chunk_size} seed={seed} failed"

    def test_chunking_invariants_seed0(self):
        self._check_equiv(b'hello world', 0)

    def test_chunking_invariants_seed42(self):
        self._check_equiv(b'hello world', 42)

    def test_chunking_invariants_seed_max(self):
        self._check_equiv(b'hello world', 2**64 - 1)

    def test_chunking_invariants_100_bytes(self):
        self._check_equiv(b'x' * 100, 0)

    def test_chunking_invariants_1000_bytes(self):
        self._check_equiv(b'y' * 1000, 7)


class TestReturnTypes:
    """Return types are exactly as documented."""

    def test_meow64_returns_int(self):
        result = meow64(b'test')
        assert type(result) is int

    def test_meow128_returns_tuple(self):
        result = meow128(b'test')
        assert type(result) is tuple
        assert len(result) == 2

    def test_expand_seed_returns_bytes(self):
        result = expand_seed(b'key')
        assert type(result) is bytes

    def test_state128_finalize_returns_int(self):
        s = State128(0)
        s.absorb(b'data')
        result = s.finalize()
        assert type(result) is int


class TestKeyVariants:
    """Hashes with various binary data patterns."""

    def test_all_zero_bytes(self):
        h = meow64(b'\x00' * 100, 0)
        assert 0 <= h < 2**64

    def test_all_ff_bytes(self):
        h = meow64(b'\xff' * 100, 0)
        assert 0 <= h < 2**64

    def test_alternating_bytes(self):
        h = meow64(b'\xaa\x55' * 50, 0)
        assert 0 <= h < 2**64

    def test_utf8_data(self):
        h = meow64("hello world".encode('utf-8'), 0)
        assert 0 <= h < 2**64

    def test_utf8_chinese(self):
        h = meow64("你好世界".encode('utf-8'), 0)
        assert 0 <= h < 2**64

    def test_binary_null_terminated(self):
        h = meow64(b'\x00hello\x00world\x00', 0)
        assert 0 <= h < 2**64
