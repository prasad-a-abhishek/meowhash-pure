# AC_TEST_MAP.md — Acceptance Criterion → Test Coverage

Every numbered acceptance criterion from `spec.md` is mapped to at least one test.

| AC | Description | Test(s) |
|----|-------------|---------|
| AC1 | `meow64(b"", seed=0)` returns a 64-bit integer in `[0, 2⁶⁴)` | `TestAC1::test_ac1_empty_input_64bit`, `TestEdgeCases::test_meow64_size_0` |
| AC2 | `meow64(b"test")` returns different hash for different seed | `TestAC2::test_ac2_meow64_test_string`, `TestAC2::test_ac2_meow64_seed1`, `TestAC8_seed_variation::test_ac8_seed0_vs_seed1` |
| AC3 | `meow64(b"") != meow64(b"a")` | `TestAC3::test_ac3_empty_vs_a` |
| AC4 | `meow64(b"abc") != meow64(b"")` | `TestAC4_meow64_abc::test_ac4_meow64_abc_not_equal_to_empty` |
| AC5 | `meow64(b"hello world")` returns 64-bit integer | `TestAC5_meow64_hello::test_ac5_meow64_hello` |
| AC6 | `meow64(b"x"*64)` aligned block handling | `TestAC6_meow64_aligned_block::test_ac6_meow64_64bytes`, `TestAC6_meow64_aligned_block::test_ac6_meow64_64bytes_deterministic` |
| AC7 | `meow64(b"x"*65)` unaligned block handling | `TestAC7_meow64_unaligned_block::test_ac7_meow64_65bytes`, `TestAC7_meow64_unaligned_block::test_ac7_meow64_65bytes_differs_from_64bytes` |
| AC8 | Different seeds → different hashes | `TestAC8_seed_variation::test_ac8_seed0_vs_seed1`, `TestAC8_seed_variation::test_ac8_seed_max` |
| AC9 | Streaming equiv to single-shot | `TestAC9_streaming_equivalence::test_ac9_streaming_single_chunk`, `TestAC9_streaming_equivalence::test_ac9_streaming_multi_chunk`, `TestAC9_streaming_equivalence::test_ac9_streaming_empty`, `TestAC9_streaming_equivalence::test_ac9_streaming_byte_by_byte`, `TestStreamingChunkingInvariants::test_chunking_invariants_*` |
| AC10 | `meow64` total safety — rejects None, non-bytes, invalid seed | `TestAC10_meow64_total_safety::test_ac10_none_data`, `TestAC10_meow64_total_safety::test_ac10_string_data`, `TestAC10_meow64_total_safety::test_ac10_int_data`, `TestAC10_meow64_total_safety::test_ac10_negative_seed`, `TestAC10_meow64_total_safety::test_ac10_seed_2pow64` |
| AC11 | `meow128` total safety — same as AC10 for 128-bit | `TestAC11_meow128_total_safety::test_ac11_none_data`, `TestAC11_meow128_total_safety::test_ac11_string_data`, `TestAC11_meow128_total_safety::test_ac11_negative_seed`, `TestAC11_meow128_total_safety::test_ac11_seed_2pow64` |
| AC12 | `expand_seed` returns 128 bytes deterministically | `TestAC12_expand_seed::test_ac12_expand_seed_length`, `TestAC12_expand_seed::test_ac12_expand_seed_deterministic`, `TestAC12_expand_seed::test_ac12_expand_seed_different_keys_different_output`, `TestAC12_expand_seed::test_ac12_expand_seed_empty_key`, `TestAC12_expand_seed::test_ac12_expand_seed_non_bytes` |
| — | Public API exports exactly 5 names | `TestAPISurface::test_public_api_exactly_four_names` |
| — | Return types correct | `TestReturnTypes::test_meow64_returns_int`, `TestReturnTypes::test_meow128_returns_tuple`, `TestReturnTypes::test_expand_seed_returns_bytes`, `TestReturnTypes::test_state128_finalize_returns_int` |
| — | Determinism | `TestDeterminism::test_meow64_deterministic_every_size`, `TestDeterminism::test_meow128_deterministic_every_size`, `TestDeterminism::test_expand_seed_deterministic_multiple_keys` |
| — | Streaming finalization invariants | `TestState128Invariants::test_state128_absorb_after_finalize_raises`, `TestState128Invariants::test_state128_finalize_twice_raises`, `TestStreamingEdgeCases::test_streaming_multiple_finalize_raises` |
| — | State128 seed validation | `TestState128Invariants::test_state128_negative_seed_raises`, `TestState128Invariants::test_state128_seed_2pow64_raises` |
| — | Large inputs | `TestPropertyBased::test_meow64_very_large_input_10mb`, `TestPropertyBased::test_meow128_very_large_input_10mb`, `TestEdgeCases::test_meow64_very_large_input`, `TestEdgeCases::test_meow128_very_large_input` |
| — | Boundary sizes (15,16,17,31,32,33,63,64,65,127,128,129,255,256) | `TestBoundaryConditions::test_meow64_size_15` … `TestBoundaryConditions::test_meow128_size_256` (18 tests) |
| — | Regression: no global state, no buffer leaks | `TestRegression::test_no_hardcoded_seeds_in_loop`, `TestRegression::test_buffer_residue_not_leaked` |

**Total: 133 tests covering all acceptance criteria plus additional property-based and regression guards.**

## Test Vector Status

Canonical MeowHash test vectors (cross-validated against the C reference with AES-NI) are **PENDING** because this pure-Python implementation cannot execute the C code and the AES-NI hardware is not available in this environment.

See `tests/test_vectors.json` for the pending vector format. Once AES-NI hardware or a compatible reference is available, run:
```bash
python3 tests/verify_test_vectors.py
```

The internal consistency of the implementation is verified by:
1. Determinism tests (same input → same output across multiple calls)
2. Streaming equivalence tests (chunked absorb == single-shot meow64/meow128)
3. Property-based tests (avalanche, distribution, collision resistance)
4. Chunking invariant tests (16 different chunk sizes × 5 data configs — all must match single-shot)
