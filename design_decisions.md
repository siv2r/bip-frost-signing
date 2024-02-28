# Design Decisions

This document provides additional reasoning behind the major design decisions in the BIP and lists alternative designs for consideration.

## Current Design
- ignored "key sorting"
- mandatory pk in nonce generation
  - after understand the vulnerability, remove this feature if the protocol remains safe

###  Minor Design
- how to write out inverse in lagrange coeff calc?
  - simply power -1
  - power power n-2
    - easy to follow
    - but makes it unclear that we are computing inverse

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

## Alternative Design Decisions

### Nonce Aggregation
- option 1: Follow FROST3 scheme (def 2.3) in ROAST paper:
  - here, co-signers won't be able to verify if their pubnonce was included in the aggnonce
    - is this neccessary?
    - This is also not possible in MuSig2 also right?
    - The aggregator can always return a garbage aggnonce
- option 2: Follow FROST paper
  - here, nonceagg function won't simply sum nonces since binding factor will vary for each signer
  - $\alpha$-pubnonces will present in session context
    - improve readability making a tupe of this and signer ids

### Correctness Condtions
- alternative 1: represent these conditions using functions?
- alternative 2: github supports latex rendering. can we represent these conditions with math symbols here?
	- will it decrease readability?
	- is latex allowed in bip spec?
- use _pubshare_ naming instead of _pub_share_?