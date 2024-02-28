# FROST signing for BIP340-compatible Threshold Signatures (BIP draft)

### Abstract

This document proposes a standard for the FROST threshold signing protocol ([paper](https://eprint.iacr.org/2020/852.pdf) and [RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)). The standard is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) public keys and signatures. It supports _tweaking_, which allows deriving [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) child keys from aggregate public keys and creating [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) Taproot outputs with key and script paths.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

TODO: some intro about frost (see rfc-draft for idea): [1] threshold property [2] verifiable like using single pubkey (like normal schnorrsig)

Certain parts of this document are reproduced from [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) due to the similarity of the FROST and MuSig2 signature schemes.

- [ ] subsections
	- [ ] motivation
	- [ ] design subsections

## Overview

- [ ] subsections
	- [ ] optionality of features
	- [ ] key generation compatibility
		TODO give a link to "frost keys" in "algorithms"
	- [ ] general signing flow
		TODO mention various keygen protocols
	- [ ] nonce generation
	- [ ] identifying disruptive signers
	- [ ] tweaking the aggregate public key

## Key Generation

This document does not provide information on the key generation method necessary for FROST signing. To learn about such methods, you can refer to [RFC-frost (Appendix D)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) and [BIP-DKG](https://github.com/BlockstreamResearch/bip-frost-dkg).

It is important to note that any FROST keys generated using the aforementioned methods must meet the correctness conditions (refer to <link subsection>) to be compatible with the signing protocol. However, it is essential to understand that the correctness conditions do not guarantee the security of these key generation methods. The conditions only ensure that the keys generated are functionally compatible with the signing protocol.

TODO will duplicating the neccessary notations here improve readability? rather than mentioning its link

### Key Specification

FROST signatures function as if they were created by an individual signer using a signing key, thus enabling them to be verified with the corresponding public key. In order to achieve this functionality, a key generation protocol divides the group signing key among each participant using Shamir secret sharing.

FROST keys produced by a key generation protocol can be represented by the following parameters:

**General parameters**

|No|Name|Type|Range (Inclusive)|Description|
|---|---|---|---|---|
|1|_max_participants_|integer|2..n|maximum number of signers allowed in the signing process|
|2|_min_participants_|integer|2..max_participants|minimum number of signers required to initiate the signing process|

**Participant parameters**

|No|Name|Type|Range (Inclusive)|Description|
|---|---|---|---|---|
|1|_id_|integer|1..max_participants|used to uniquely identify each participant, must be distinct from the _id_ of every other participant|
|2|_sec_share_<sub>id</sub>|integer (scalar)|1..n|signing key of a participant|
|3|_pub_share_<sub>id</sub>|curve point (_plain public key_)|shouldn't be infinity point|public key associated with the above signing key|
|4|_group_pubkey_|curve point (_plain public key_)|shouldn't be infinity point|group public key used to verify the BIP340 Schnorr signature produced by the FROST-signing protocol|

### Correctness Conditions

TODO alternatively represent these conditions using functions?

todo use _pubshare_ naming instead of _pub_share_?

The notations used in this section can be found in _todo link_

#### Public shares condition

For each participants _i_ in the range \[_1..max_participants_], their public share must equal to their secret share scalar multiplied with the generator point, represented as: _pub_share<sub>i</sub> = sec_share<sub>i</sub>⋅G_

#### Group public key condition

Consider a set of participants, denoted by _T_, chosen from a total pool of participants whose size is _max_participants_. For this set _T_, we can define a special parameter called the "group secret key". It is calculated by summing the secret share and Lagrange coefficient for each participant in T:

_group_seckey_ = sum (_lagrange_coeff<sub>j, T</sub>_._sec_share_<sub>j</sub>) mod _n_, for every _j_ in _T_

For all possible values of T, the group public key must equal to their group secret key scalar multiplied by the generator point represented as _group_pubkey<sub>i</sub>_ = _group_seckey<sub>j, T</sub>_⋅_G_.

## Algorithms

The following specification of the algorithms has been written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation and space. In particular, some values are recomputed but can be cached in actual implementations (todo see _mention link here_).

### Notation

The following conventions are used, with constants as defined for [secp256k1](https://www.secg.org/sec2-v2.pdf). We note that adapting this proposal to other elliptic curves is not straightforward and can result in an insecure scheme.

- Lowercase variables represent integers or byte arrays.
    - The constant _p_ refers to the field size, _0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_.
    - The constant _n_ refers to the curve order, _0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_.
    - The constant _num_participants_ refers to number of participants involved in the signing process, must be at least _min_participants_ but must not be larger than _max_participants_.
- Uppercase variables refer to points on the curve with equation _y<sup>2</sup> = x<sup>3</sup> + 7_ over the integers modulo _p_.
    - _is_infinite(P)_ returns whether _P_ is the point at infinity.
    - _x(P)_ and _y(P)_ are integers in the range _0..p-1_ and refer to the X and Y coordinates of a point _P_ (assuming it is not infinity).
    - The constant _G_ refers to the base point, for which _x(G) = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_ and _y(G) = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_.
    - Addition of points refers to the usual [elliptic curve group operation](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law).
    - [Multiplication (⋅) of an integer and a point](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication) refers to the repeated application of the group operation.
- Functions and operations:
    - _||_ refers to byte array concatenation.
    - The function _x[i:j]_, where _x_ is a byte array and _i, j ≥ 0_, returns a _(j - i)_-byte array with a copy of the _i_th byte (inclusive) to the _j_th byte (exclusive) of _x_.
    - The function _bytes(n, x)_, where _x_ is an integer, returns the n-byte encoding of _x_, most significant byte first.
    - The constant _empty_bytestring_ refers to the empty byte array. It holds that _len(empty_bytestring) = 0_.
    - The function _xbytes(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _bytes(32, x(P))_.
    - The function _len(x)_ where _x_ is a byte array returns the length of the array.
    - The function _has_even_y(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _y(P) mod 2 == 0_.
    - The function _with_even_y(P)_, where _P_ is a point, returns _P_ if _is_infinite(P)_ or _has_even_y(P)_. Otherwise, _with_even_y(P)_ returns _-P_.
    - The function _cbytes(P)_, where _P_ is a point for which _not is_infinite(P)_, returns _a || xbytes(P)_ where _a_ is a byte that is _2_ if _has_even_y(P)_ and _3_ otherwise.
    - The function _cbytes_ext(P)_, where _P_ is a point, returns _bytes(33, 0)_ if _is_infinite(P)_. Otherwise, it returns _cbytes(P)_.
    - The function _int(x)_, where _x_ is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is _x_.
    - The function _lift_x(x)_, where _x_ is an integer in range _0..2<sup>256</sup>-1_, returns the point _P_ for which _x(P) = x<sup>todo add ref here</sup>_ and _has_even_y(P)_, or fails if _x_ is greater than _p-1_ or no such point exists. The function _lift_x(x)_ is equivalent to the following pseudocode: TODO: add footnote
		- Fail if _x > p-1_.
		- Let _c = x<sup>3</sup> + 7 mod p_.
		- Let _y' = c<sup>(p+1)/4</sup> mod p_.
		- Fail if _c ≠ y'<sup>2</sup> mod p_.
		 - Let _y = y'_ if _y' mod 2 = 0_, otherwise let _y = p - y'_ .
		- Return the unique point _P_ such that _x(P) = x_ and _y(P) = y_.
    - The function _cpoint(x)_, where _x_ is a 33-byte array (compressed serialization), sets _P = lift_x(int(x[1:33]))_ and fails if that fails. If _x[0] = 2_ it returns _P_ and if _x[0] = 3_ it returns _-P_. Otherwise, it fails.
    - The function _cpoint_ext(x)_, where _x_ is a 33-byte array (compressed serialization), returns the point at infinity if _x = bytes(33, 0)_. Otherwise, it returns _cpoint(x)_ and fails if that fails.
    - The function _hash<sub>tag</sub>(x)_ where _tag_ is a UTF-8 encoded tag name and _x_ is a byte array returns the 32-byte hash _SHA256(SHA256(tag) || SHA256(tag) || x)_.
    - todo lagrange coefficient
- Other:
    - Tuples are written by listing the elements within parentheses and separated by commas. For example, _(2, 3, 1)_ is a tuple.

TODO remove unused functions above

### Tweaking Group Public Key

#### Tweak Context

The Tweak Context is a data structure consisting of the following elements:

- The point _Q_ representing the potentially tweaked group public key: an elliptic curve point
- The accumulated tweak _tacc_: an integer with _0 ≤ tacc < n_
- The value _gacc_: 1 or -1 mod n

We write "Let _(Q, gacc, tacc) = tweak_ctx_" to assign names to the elements of a Tweak Context.

Algorithm _TweakCtxInit(group_pk):_
- Input:
    - The group public key _group_pk_: u 33-byte arrays
- Let _Q = cpoint(group_pk)_
- Fail if _is_infinite(Q)_.
- Let _gacc = 1_
- Let _tacc = 0_
- Return _tweak_ctx = (Q, gacc, tacc)_.

Algorithm _GetXonlyPubkey(tweak_ctx)_:
- Let _(Q, _, _) = tweak_ctx_
- Return _xbytes(Q)_

Algorithm _GetPlainPubkey(tweak_ctx)_:
- Let _(Q, _, _) = tweak_ctx_
- Return _cbytes(Q)_

#### Applying Tweaks

Algorithm _ApplyTweak(tweak_ctx, tweak, is_xonly_t)_:
- Inputs:
    - The _tweak_ctx_: a Tweak Context (todo link the defn) data structure
    - The _tweak_: a 32-byte array
    - The tweak mode _is_xonly_t_: a boolean
- Let _(Q, gacc, tacc) = tweak_ctx_
- If _is_xonly_t_ and _not has_even_y(Q)_:
    - Let _g = -1 mod n_
- Else:
    - Let _g = 1_
- Let _t = int(tweak)_; fail if _t ≥ n_
- Let _Q' = g⋅Q + t⋅G_
    - Fail if _is_infinite(Q')_
- Let _gacc' = g⋅gacc mod n_
- Let _tacc' = t + g⋅tacc mod n_
- Return _tweak_ctx' = (Q', gacc', tacc')_

### Nonce Generation

todo: include participant identifier too?

Algorithm _NonceGen(sec_share, pub_share, group_pk, m, extra_in)_:
- Inputs:
    - The participant’s secret signing key _sec_share_: a 32-byte array (optional argument)
    - The corresponding public key _pub_share_: a 33-byte array (see _subsection link_ for the reason that this argument is mandatory)
    - The x-only group public key grou__pk_: a 32-byte array (optional argument)
    - The message _m_: a byte array (optional argument)
    - The auxiliary input _extra_in_: a byte array with _0 ≤ len(extra_in) ≤ 2<sup>32</sup>-1_ (optional argument)
- Let _rand'_ be a 32-byte array freshly drawn uniformly at random
- If the optional argument _sec_share_ is present:
    - Let _rand_ be the byte-wise xor of _sec_share_ and _hash<sub>FROST/aux</sub>(rand')_
- Else:
    - Let _rand = rand'_
- If the optional argument _group_pk_ is not present:
    - Let _group_pk = empty_bytestring_
- If the optional argument _m_ is not present:
    - Let _m_prefixed = bytes(1, 0)_
- Else:
    - Let _m_prefixed = bytes(1, 1) || bytes(8, len(m)) || m_
- If the optional argument _extra_in_ is not present:
    - Let _extra_in = empty_bytestring_
- Let _k<sub>i</sub> = int(hash<sub>FROST/nonce</sub>(rand || bytes(1, len(pub_share)) || pub_share || bytes(1, len(group_pk)) || group_pk || m_prefixed || bytes(4, len(extra_in)) || extra_in || bytes(1, i - 1))) mod n_ for _i = 1,2_
- Fail if _k<sub>1</sub> = 0_ or _k<sub>2</sub> = 0_
- Let _R<sub>⁎,1</sub> = k1⋅G, R<sub>⁎,2</sub> = k2⋅G_
- Let _pubnonce = cbytes(R<sub>,1</sub>) || cbytes(R<sub>⁎,2</sub>)_
- Let _secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>) || pk_
- Return _(secnonce, pubnonce)_

### Nonce Aggregation

Algorithm _NonceAgg(pubnonce<sub>1..u</sub>)_:
- Inputs:
    - The number of signers _u_: an integer with _min_participants ≤ u ≤ max_participants_
    - The public nonces _pubnonce<sub>1..u</sub>_: _u_ 66-byte arrays
- For _j = 1 .. 2_:
    - For _i = 1 .. u_:
        - Let _R<sub>i,j</sub> = cpoint(pubnonce<sub>i</sub>[(j-1)_33:j_33])_; fail if that fails and blame signer _i_ for invalid _pubnonce_.
    - Let _R<sub>j</sub> = R<sub>1,j</sub> + R<sub>2,j</sub> + ... + R<sub>u,j</sub>_
- Return _aggnonce = cbytes_ext(R<sub>1</sub>) || cbytes_ext(R<sub>2</sub>)_

### Session Context

The Session Context is a data structure consisting of the following elements:

- The number _u_ of signers with _min_participants ≤ u ≤ max_participants_
- The participant identifiers of signers _id<sub>1..u</sub>: _u_ integers with 1 _≤ id<sub>i</sub> ≤ max_participants_
- The aggregate public nonce of signers _aggnonce_: a 66-byte array
- The group public key _group_pk_: _u_ 33-byte arrays
- The number _v_ of tweaks with _0 ≤ v < 2^32_
- The tweaks _tweak<sub>1..v</sub>_: _v_ 32-byte arrays
- The tweak modes _is_xonly_t<sub>1..v</sub>_ : _v_ booleans
- The message _m_: a byte array

We write "Let _(u, id<sub>1..u</sub>, aggnonce, group_pk, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx_" to assign names to the elements of a Session Context.

Algorithm _GetSessionValues(session_ctx)_:
- Let _(u, id<sub>1..u</sub>, aggnonce, group_pk, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx_
- Let _tweak_ctx<sub>0</sub> = TweakCtxInit(group_pk)_; fail if that fails
- For _i = 1 .. v_:
    - Let _tweak_ctx<sub>i</sub> = ApplyTweak(tweak_ctx<sub>i-1</sub>, tweak<sub>i</sub>, is_xonly_t<sub>i</sub>)_; fail if that fails
- Let _(Q, gacc, tacc) = tweak_ctx<sub>v</sub>_
- Let _b = int(hash<sub>FROST/noncecoef<sub>(aggnonce || xbytes(Q) || m)) mod n_
- Let _R1 = cpoint_ext(aggnonce[0:33]), R2 = cpoint_ext(aggnonce[33:66])_; fail if that fails and blame nonce aggregator for invalid _aggnonce_.
- Let _R' = R1 + b⋅R2_
- If _is_infinite(R'):_
    - _Let final nonce_ R = G _(see dealing with inf nonce agg link)_
- _Else:_
    - _Let final nonce_ R = R'
- Let _e = int(hash<sub>BIP0340/challenge<sub>((xbytes(R) || xbytes(Q) || m)) mod n_
- _Return_ (Q, gacc, tacc, b, R, e)

Algorithm _GetSessionLagrangeCoeff(session_ctx, my_id)_:
- Let _(u, id<sub>1..u</sub>, _, _, _, _, _) = session_ctx_
- Fail if _my_id_ not in _id<sub>1..u</sub>_
- Return _LagrangeCoeff(id<sub>1..u</sub>, my_id)_

Internal Algorithm _LagrangeCoeff(id<sub>1..u</sub>, my_id):_
- Let _lambda = 0_
- For _i = 1..u_:
    - Let _num_ = _id<sub>i</sub>_
    - Let _den_ = _id<sub>i</sub> - my_id_
    - _lambda_ = (_lambda + num.deno<sup>-1</sup>) mod n_
- Return _lambda_



---------

- [ ] Signing
- [ ] Partial Signature Verification
- [ ] Partial Signature Aggregation
- [ ] Test Vectors & Reference Code

## Remarks on Security and Correctness

## Backwards Compatibility

This document proposes a standard for the FROST threshold signature scheme that is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). FROST is _not_ compatible with ECDSA signatures traditionally used in Bitcoin.

## Footnotes

## Acknowledgments

