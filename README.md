# FROST for BIP340-compatible Threshold Signatures (BIP draft)

### Abstract

This document proposes a standard for the FROST threshold signature scheme ([paper](https://eprint.iacr.org/2020/852.pdf) and [RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)). The standard is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) public keys and signatures. It supports _tweaking_, which allows deriving [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) child keys from aggregate public keys and creating [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) Taproot outputs with key and script paths.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

Certain parts of this document are reproduced from the [MuSig2 BIP](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) because of the similarities between the FROST and MuSig2 signature schemes.

- [ ] subsections
	- [ ] motivation
	- [ ] design subsections

## Overview

- [ ] subsections
	- [ ] optionality of features
	- [ ] general signing flow
	- [ ] share generation
	- [ ] nonce generation
	- [ ] identifying disruptive signers
	- [ ] tweaking the aggregate public key

## Algorithms

- [ ] Notation
- [ ] Share Generation
	- [ ] SSS (Trusted Dealer)
	- [ ] BIP DKG
- [ ] Nonce Generation
- [ ] Nonce Aggregation
- [ ] Session Context
- [ ] Signing
- [ ] Partial Signature Verification
- [ ] Partial Signature Aggregation
- [ ] Test Vectors & Reference Code

## Remarks on Security and Correctness

## Backwards Compatibility

This document proposes a standard for the FROST threshold signature scheme that is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). FROST is _not_ compatible with ECDSA signatures traditionally used in Bitcoin.

## Footnotes

## Acknowledgments

