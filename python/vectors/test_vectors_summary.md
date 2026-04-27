# FROST Test Vectors

This directory contains JSON test vectors for the BIP-FROST signing
protocol. They are consumed by `python/tests.py` and are intended for
cross-implementation compatibility testing.

## Files

| File | Function under test | Top-level shape |
|---|---|---|
| `nonce_gen_vectors.json` | `nonce_gen_internal` | flat `test_cases[]` |
| `nonce_agg_vectors.json` | `nonce_agg` | shared `pubnonces[]` + `valid_test_cases` + `error_test_cases` |
| `sign_verify_vectors.json` | `sign` and `partial_sig_verify` | shared setup + `valid_test_cases` + `sign_error_test_cases` + `verify_fail_test_cases` + `verify_error_test_cases` |
| `tweak_vectors.json` | `sign` under tweak combinations | shared setup + `valid_test_cases` + `error_test_cases` |
| `det_sign_vectors.json` | `deterministic_sign` | shared setup + `valid_test_cases` + `error_test_cases` (tweaks inline per case) |
| `sig_agg_vectors.json` | `partial_sig_agg` producing a BIP340 signature | shared setup + `valid_test_cases` + `error_test_cases` |

## Conventions

### Fixed FROST keys

Every file except `nonce_gen_vectors.json` and `nonce_agg_vectors.json`
reuses the same FROST key material, defined by `frost_keygen_fixed()` in
`python/gen_vectors.py`: `n = 3`, `t = 2`, `threshold_pubkey =
03B026…D69237`, `identifiers = [0, 1, 2]`. Three real pubshares are
followed by a fourth bogus pubshare (`0200…0007`) used to drive
"invalid pubshare" error cases. Only the first signer's secret share
(`secshare_p0`) is exposed — all valid cases sign from signer 0's
perspective (or signer 1 in a reorder-invariance case). `secnonces_p0`
may include extra entries (e.g. an all-zero entry) used exclusively to
drive nonce-reuse / out-of-range error cases. Sharing the same
`threshold_pubkey` across files lets the vectors be read as one
consistent FROST setup.

### Top-level pools and indexing

Test cases do not inline ids, pubshares, pubnonces, aggnonces, tweaks,
or messages. Each file declares pools at the top level, and individual
cases reference them via `id_indices`, `pubshare_indices`,
`pubnonce_indices`, `tweak_indices`, `aggnonce_index`, `msg_index`,
`secnonce_index`, and `signer_index`. `signer_index` is an index into
the *case's own* `id_indices` list (i.e. which entry in the per-case
signer set is the one signing), not into the top-level pool.
`sig_agg_vectors.json` keeps `psigs` and `aggnonce` inline per case
because psigs are case-specific outputs and only one aggnonce is needed.
`det_sign_vectors.json` keeps `tweaks` and `aggothernonce` inline per
case for similar reasons.

### Test cases

Cases fall into one of four categories. `valid_test_cases` must succeed
and produce the exact bytes given in `expected`. `error_test_cases` and
`sign_error_test_cases` must raise the exception described in the
`error` object. `verify_fail_test_cases` must cause `partial_sig_verify`
to return `False` without raising. `verify_error_test_cases` must cause
`partial_sig_verify` to raise. The `error` object takes one of two
shapes:

```json
{ "type": "ValueError", "message": "<exact message string>" }
```

```json
{ "type": "InvalidContributionError",
  "signer_index": <int or null>,
  "contrib": "pubnonce" | "aggnonce" | "aggothernonce" | "psig" }
```

`signer_index` inside an `InvalidContributionError` is `null` when the
faulty contribution is aggregator-level (e.g. an `aggnonce` or
`aggothernonce`) rather than tied to a specific signer. When a case
exercises a signer whose id is *not* present in the participant list,
the case sets `signer_index: null` and provides `signer_id` directly,
since the id cannot be looked up by index.
