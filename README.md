# FROST for BIP340-compatible Threshold Signatures (BIP draft)

### Abstract

This document proposes a standard for the FROST threshold signature scheme ([paper](https://eprint.iacr.org/2020/852.pdf) and [RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)). The standard is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) public keys and signatures. It supports _tweaking_, which allows deriving [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) child keys from aggregate public keys and creating [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) Taproot outputs with key and script paths.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

Certain parts of this document are reproduced from [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) because of the similarities between the FROST and MuSig2 signature schemes.

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

The following specification of the algorithms has been written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation and space. In particular, some values are recomputed but can be cached in actual implementations (see _mention link here_).

TODO: check the relevance of the last line above, after completing this section.

### Notation

The following conventions are used, with constants as defined for [secp256k1](https://www.secg.org/sec2-v2.pdf). We note that adapting this proposal to other elliptic curves is not straightforward and can result in an insecure scheme.

- Lowercase variables represent integers or byte arrays.
    - The constant _p_ refers to the field size, _0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_.
    - The constant _n_ refers to the curve order, _0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_.
- Uppercase variables refer to points on the curve with equation _y2 = x3 + 7_ over the integers modulo _p_.
    - _is_infinite(P)_ returns whether _P_ is the point at infinity.
    - _x(P)_ and _y(P)_ are integers in the range _0..p-1_ and refer to the X and Y coordinates of a point _P_ (assuming it is not infinity).
    - The constant _G_ refers to the base point, for which _x(G) = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_ and _y(G) = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_.
    - Addition of points refers to the usual [elliptic curve group operation](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law).
    - [Multiplication (⋅) of an integer and a point](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication) refers to the repeated application of the group operation.
- Functions and operations:
    - _||_ refers to byte array concatenation.
    - The function _x[i:j]_, where _x_ is a byte array and _i, j ≥ 0_, returns a *(j - i)*byte array with a copy of the _i_th byte (inclusive) to the _j_th byte (exclusive) of _x_.
    - The function _bytes(n, x)_, where _x_ is an integer, returns the n-byte encoding of _x_, most significant byte first.
    - The constant _empty_bytestring_ refers to the empty byte array. It holds that _len(empty_bytestring) = 0_.
    - The function _xbytes(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _bytes(32, x(P))_.
    - The function _len(x)_ where _x_ is a byte array returns the length of the array.
    - The function _has_even_y(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _y(P) mod 2 == 0_.
    - The function _with_even_y(P)_, where _P_ is a point, returns _P_ if _is_infinite(P)_ or _has_even_y(P)_. Otherwise, _with_even_y(P)_ returns _P_.
    - The function _cbytes(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _a || xbytes(P)_ where _a_ is a byte that is _2_ if _has_even_y(P)_ and _3_ otherwise.
    - The function _cbytes_ext(P)_, where _P_ is a point, returns _bytes(33, 0)_ if _is_infinite(P)_. Otherwise, it returns _cbytes(P)_.
    - The function _int(x)_, where _x_ is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is _x_.
    - The function _lift_x(x)_, where _x_ is an integer in range _0..22561_, returns the point _P_ for which _x(P) = x_ and _has_even_y(P)_, or fails if _x_ is greater than _p-1_ or no such point exists. The function _lift_x(x)_ is equivalent to the following pseudocode: TODO: add footnote
		- Fail if _x > p-1_.
		- Let _c = x3 + 7 mod p_.
		- Let _y' = c(p+1)/4 mod p_.
		- Fail if _c ≠ y'2 mod p_.
		 - Let _y = y'_ if _y' mod 2 = 0_, otherwise let _y = p - y'_ .
		- Return the unique point _P_ such that _x(P) = x_ and _y(P) = y_.
    - The function _cpoint(x)_, where _x_ is a 33-byte array (compressed serialization), sets _P = lift_x(int(x[1:33]))_ and fails if that fails. If _x[0] = 2_ it returns _P_ and if _x[0] = 3_ it returns _P_. Otherwise, it fails.
    - The function _cpoint_ext(x)_, where _x_ is a 33-byte array (compressed serialization), returns the point at infinity if _x = bytes(33, 0)_. Otherwise, it returns _cpoint(x)_ and fails if that fails.
    - The function _hashtag(x)_ where _tag_ is a UTF-8 encoded tag name and _x_ is a byte array returns the 32-byte hash _SHA256(SHA256(tag) || SHA256(tag) || x)_.
- Other:
    - Tuples are written by listing the elements within parentheses and separated by commas. For example, _(2, 3, 1)_ is a tuple.

TODO remove unused functions above

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

