# Design Decisions

This document provides additional reasoning behind the major design decisions in the BIP and lists alternative designs for consideration.

## Current Design
- ignored "key sorting"
- mandatory pk in nonce generation
  - after understand the vulnerability, remove this feature if the protocol remains safe

## TBD Design Decisions

### Key Sorting
- does this make sense for FROST?
- MuSig2's aggregate key generation depends on order of n-pubkeys
- This doesn't seem to be the case for FROST
  - true, in context of trusted dealer
  - check this statement in context of DKG

### Mandatory pk in NonceGen
- this vulnerability doesn't seem to affect frost (at least in trusted dealer)
  - see [this bitcoin-dev list mail](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-October/021000.html)
- does this affect DKG?
  - first impression: mostly no. Let A, B be two pubshares. Solving for t (tweak) in _A = B + tG_ requires breaking DLog.
  - So, the condition 2 mentioned in the mailing list doesn't satisfy?

## Commit to Singer set in Nonce Gen
- nonce generation doesn't required knowledge of the signer's set (as of now)
  - this would prevent us from preprocessing the round 1
  - but nonce aggregation needs to commit to the signer's set