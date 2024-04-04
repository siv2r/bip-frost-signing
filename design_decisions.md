# Design Decisions

This document provides additional reasoning behind the major design decisions in the BIP and lists alternative designs for consideration.

## Signing Flow

![General Signing Flow](images/frost-signing-flow.png)

## Current Design

### Key Generation

We aim to represent $(t, n)$ FROST keys using [1] input/output arguments of keygen and [2] conditions that output arguments must satisfy (see definition 2.5 in the [ROAST paper](https://eprint.iacr.org/2022/550.pdf)). This representation should be easy to understand without sacrificing precision. I am currently trying to improve the way we represent correctness conditions. At present, we represent them in an English-math like language to make it easier for non-mathematicians to understand. However, I am open to other ways to represent them. Here are two alternatives:

Alternative 1: We could represent these conditions using boolean functions. In this case, we would say that the key generation is compatible with this BIP if these functions return true.

Alternative 2: Since Github supports LaTeX, could we represent these conditions as LaTeX equations? Does BIP allow for this?

### No Key Sorting

MuSig2's [KeyAgg](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-Key_Generation_and_Aggregation) produces an aggregate public key (aka group public key), which depends on the order of the individual public keys. To ensure that the aggregate public key is independent of the individual public key order, it provides a [KeySort](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-Key_Sorting) mechanism. This mechanism defines a canonical order, which ensures that the aggregate public key remains the same regardless of the order of individual public keys.

In FROST, the order of the public shares does not affect the group public key created by aggregating the signer's public share, so no sorting mechanism is needed.

### Tweak Context

To ensure compatibility with various key generation methods, we have avoided the KeyAgg context mentioned in MuSig2 BIP. Instead, we define the Tweak Context, which must be initialized with the group public key when users wish to tweak it.

### No Mandatory PK in Nonce Generation

MuSig2 requires the public key to be given as an input argument for nonce generation. This is done to prevent a vulnerability that arises when a user attempts to sign with their tweaked individual public key. ( See [mailing list](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-October/021000.html) & [this bip324 section](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#signing-with-tweaked-individual-keys)).

On the other hand, FROST does not have a non-interactive key aggregation mechanism like MuSig2, which means this vulnerability does not affect it. Hence, we do not mandate the public share argument during nonce generation.

### Nonce Aggregation

We use the nonce aggregation technique described in the FROST3 scheme (see section 2.3 in [ROAST paper](https://eprint.iacr.org/2022/550.pdf)), which is a variant of the original [FROST](https://eprint.iacr.org/2020/852.pdf). The advantage of using FROST3 is that all co-signers involved in the signing process share the same binding factor, which makes the nonce aggregation process simpler.

An alternative approach is to follow the original FROST protocol, where the aggregator does not perform the aggregation. Instead, it sends the set $\bigcup \limits_{i=1}^{u}{(i, R_{i, 1}, R_{i, 2})}$ to each signer. The disadvantage is that the size of this set is $(32+33+33) \times u$ bytes, which is larger than the 66-byte aggregate nonce sent in the FROST3 scheme. The advantage is that signers can detect a malicious aggregator when their nonce commitment is absent in this set. However, this detection mechanism cannot validate the set when some signers collude with the malicious aggregator.

### Session Context Structure

There are two ways to store the group public key in the Session context data structure.
- Option 1: The Session context contains individual public shares for each participant involved in the signing process. Whenever we need the group public key, we call the _GetSessionGroupPubkey_ algorithm.
- Option 2: The Session context contains the group public key itself.

I chose Option 1 because it fits nicely with the _PartialSigVerify_ algorithm which requires the list of individual public shares.

## Some Bike Shedding
- how to write out inverse in lagrange coeff calc?
  - simply power -1
  - power power n-2
    - easy to follow
    - but makes it unclear that we are computing inverse
- for computing nonce coefficient (_b_) each participant identifier is encoded as 32-bytes array
  - The `id` value is a scalar. So, it should be 32-byte right?
- hash tag for b, "noncecoef" vs "noncecoeff"

## Todo List
- [ ] reference implementation & test vectors
- [x] flowchart for general signing flow
- [ ] improve FROST key representation
- [ ] add footnotes