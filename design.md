This document provides reasoning behind the major design decisions in the BIP and lists alternative designs for consideration.

## General Signing Flow

![General Signing Flow](docs/signing_flow.png)

## Current Design

In this BIP, we follow the FROST3 scheme (see section 2.3 in [ROAST paper](https://eprint.iacr.org/2022/550.pdf)), which is a variant of the [original FROST](https://eprint.iacr.org/2020/852.pdf).

TODO: update this section to reflect that we currently follow the alternative 1 instead.
### Key Generation

We aim to represent $(t, n)$ FROST keys using [1] input/output arguments of keygen and [2] conditions that output arguments must satisfy (see definition 2.5 in the [ROAST paper](https://eprint.iacr.org/2022/550.pdf)). This representation should be easy to understand without sacrificing precision. At present, we represent these conditions using boolean functions _ValidateGroupPubkey_ and _ValidatePubshares_.

### No Key Sorting

MuSig2's [KeyAgg](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-Key_Generation_and_Aggregation) produces an aggregate public key (aka group public key), which depends on the order of the individual public keys. To ensure that the aggregate public key is independent of the individual public key order, it provides a [KeySort](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-Key_Sorting) mechanism. This mechanism defines a canonical order, which ensures that the aggregate public key remains the same regardless of the order of individual public keys.

In FROST, the order of the public shares does not affect the group public key created by aggregating the signer's public share, so no sorting mechanism is needed.

### Group Pubkey Type

If a key generation method produces a group public key incompatible with BIP340 (i.e., a plain pubkey), it doesn't automatically render the method incompatible with our signing protocol. Hence, we allow the keygen to produce the group public key as `PlainPk` (33 bytes) instead of `XonlyPk` (32 bytes). For example, BIP-FROST-DKG outputs a `PlainPk` not `XonlyPk`.

It is crucial to note that the signatures generated through our [signing protocol](README.md#signing) are only verifiable with a BIP340 compatible group pubkey. Therefore, if you are using a key generation method that outputs a `PlainPk` type group pubkey, you need to convert it to `XonlyPk` using the [`secp256k1_xonly_pubkey_from_pubkey`](https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_extrakeys.h#L93) API (TODO change this sentence, sign algo takes care of this).

### Tweak Context

To ensure compatibility with various key generation methods, we have avoided the KeyAgg context mentioned in MuSig2 BIP. Instead, we define the Tweak Context, which must be initialized with the group public key when users wish to tweak it.

### No Mandatory PK in Nonce Generation

MuSig2 requires the public key to be given as an input argument for nonce generation. This is done to prevent a vulnerability that arises when a user attempts to sign with their tweaked individual public key. (See [mailing list](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-October/021000.html), [bip324 section](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#signing-with-tweaked-individual-keys), and [this writeup](https://github.com/jonasnick/musig2-tweaking)).

The above vulnerability is exploited by creating rogue keyagg coefficients (that adds up to a rogue bip340 challenge) using wagner's algorithm. FROST does not rely on any non-interactive key aggregation mechanism (i.e., no key agg coeffs involved), meaning this vulnerability does not affect it. Hence, we do not mandate the public share argument during nonce generation.

### Nonce Aggregation

We use the nonce aggregation technique described in the FROST3 scheme. The advantage here is that all co-signers involved in the signing process will create the same binding factor, which makes the nonce aggregation process simpler.

An alternative approach is to follow the original FROST protocol, where the aggregator does not perform the aggregation. Instead, it sends the set $\bigcup \limits_{i=1}^{u}{(i, R_{i, 1}, R_{i, 2})}$ to each signer. The disadvantage is that the size of this set is $(32+33+33) \times u$ bytes, which is larger than the 66-byte aggregate nonce sent in the FROST3 scheme. The advantage is that signers can detect a malicious aggregator when their nonce commitment is absent in this set. However, this detection mechanism cannot validate the set when some signers collude with the malicious aggregator.

### Session Context Structure

There are two ways to store the group public key in the Session context data structure.
- Option 1: The Session context contains individual public shares for each participant involved in the signing process. Whenever we need the group public key, we call the _GetSessionGroupPubkey_ algorithm.
- Option 2: The Session context contains the group public key itself.

I chose Option 1 because it fits nicely with the _PartialSigVerify_ algorithm which requires the list of individual public shares.

### Sorting Ids While Signing

The FROST3 scheme computes the binding factor as
```math
b = H_{non}(T, \text{group\_pk}, \text{aggnonce}, \text{msg})
```
where $T$ represents the signer set. Since $T$ is a set, it must be independent of the order of signers, i.e., {1, 2, 3} = {2, 1, 3}. Therefore, we sort the IDs (see [_GetSessionValues_](README.md#session-context)) when computing the binding factor.

## Some Bike Shedding
- how to write out inverse in lagrange coeff calc?
  - simply power -1
  - power power n-2
    - easy to follow
    - but makes it unclear that we are computing inverse
- what should be limit for MAX_PARTICIPANTS?
  - we should use 32-byte array for it
  - The frost draft says this:
    > MAX_PARTICIPANTS MUST be a positive integer less than the group order
- should ARG_CHECK the `ids[i]` when converting it from `bytes` to `ints`?
  - If yes, how to blame the singer if their `id` itself is incorrect?
- hash tag for b, "noncecoef" vs "noncecoeff"
  - follow musig2. It uses "noncecoef"
- we currently use the symbol &lambda; in Sign & ParialSigVerify. Is it okay? Or should we use an ASCII char instead?
