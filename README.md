```
BIP:
Title: FROST Signing for BIP340-compatible Threshold Signatures
Author: Sivaram Dhakshinamoorthy <siv2ram@gmail.com>
Status: Draft
License: CC0-1.0
License-Code: MIT
Type: Informational
Created:
Post-History:
Comments-URI:
```

# FROST Signing for BIP340-compatible Threshold Signatures

### Abstract

This document proposes a standard for the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol. The standard is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) public keys and signatures. It supports _tweaking_, which allows deriving [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) child keys from the group public key and creating [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) Taproot outputs with key and script paths.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

This document proposes the FROST signing protocol based on the FROST3 variant (see section 2.3) introduced in ROAST[[RRJSS22](https://eprint.iacr.org/2022/550)], instead of the original FROST[[KG20](https://eprint.iacr.org/2020/852)]. Key generation for FROST signing is out of scope for this document. However, we specify the requirements that a key generation method must satisfy to be compatible with this signing protocol.

Many sections of this document have been directly copied or modified from [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) due to the similarities between the FROST3 and [MuSig2](https://eprint.iacr.org/2020/1261.pdf) signature schemes.

### Motivation

The FROST signature scheme [[KG20](https://eprint.iacr.org/2020/852),[CKM21](https://eprint.iacr.org/2021/1375),[BTZ21](https://eprint.iacr.org/2022/833),[CGRS23](https://eprint.iacr.org/2023/899)] enables _t-of-n_ Schnorr threshold signatures, in which a threshold _t_ of some set of _n_ signers is required to produce a signature.
FROST remains unforgeable as long as at most _t-1_ signers are compromised, and remains functional as long as _t_ honest signers do not lose their secret key material. It supports any choice of _t_ as long as _1 ≤ t ≤ n_.[^t-edge-cases]

The primary motivation is to create a standard that allows users of different software projects to jointly control Taproot outputs ([BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)).
Such an output contains a public key which, in this case, would be the group public key derived from the public shares of threshold signers.
It can be spent using FROST to produce a signature for the key-based spending path.

The on-chain footprint of a FROST Taproot output is essentially a single BIP340 public key, and a transaction spending the output only requires a single signature cooperatively produced by _threshold_ signers. This is **more compact** and has **lower verification cost** than signers providing _n_ individual public keys and _t_ signatures, as would be required by an _t-of-n_ policy implemented using <code>OP_CHECKSIGADD</code> as introduced in ([BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)).
As a side effect, the numbers _t_ and _n_ of signers are not limited by any consensus rules when using FROST.

Moreover, FROST offers a **higher level of privacy** than <code>OP_CHECKSIGADD</code>: FROST Taproot outputs are indistinguishable for a blockchain observer from regular, single-signer Taproot outputs even though they are actually controlled by multiple signers. By tweaking a group public key, the shared Taproot output can have script spending paths that are hidden unless used.

There are threshold-signature schemes other than FROST that are fully compatible with Schnorr signatures.
The FROST variant proposed below stands out by combining all the following features:
* **Two Communication Rounds**: FROST is faster in practice than other threshold-signature schemes [[GJKR03](https://link.springer.com/chapter/10.1007/3-540-36563-x_26)] which requires at least three rounds, particularly when signers are connected through high-latency anonymous links. Moreover, the need for fewer communication rounds simplifies the algorithms and reduces the probability that implementations and users make security-relevant mistakes.
* **Efficiency over Robustness**: FROST trades off the robustness property for network efficiency (fewer communication rounds), requiring the protocol to be aborted in the case of any misbehaving participant.
* **Provable security**: FROST3 with an idealized key generation (i.e., trusted setup) has been [proven existentially unforgeable](https://eprint.iacr.org/2022/550.pdf) under the one-more discrete logarithm (OMDL) assumption (instead of the discrete logarithm assumption required for single-signer Schnorr signatures) in the random oracle model (ROM).

### Design

* **Compatibility with BIP340**: The group public key and participant public shares produced by a compatible key generation algorithm MUST be _plain_ public keys in compressed format. In this proposal, the signature output at the end of the signing protocol is a BIP340 signature, which passes BIP340 verification for the BIP340 X-only version of the group public key and a message.
* **Tweaking for BIP32 derivations and Taproot**: This proposal supports tweaking group public key and signing for this tweaked group public key. We distinguish two modes of tweaking: _Plain_ tweaking can be used to derive child group public keys per [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)._X-only_ tweaking, on the other hand, allows creating a [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) tweak to add script paths to a Taproot output. See [tweaking the group public key](./README.md#tweaking-group-public-key) below for details.
* **Non-interactive signing with preprocessing**: The first communication round, exchanging the nonces, can happen before the message or the exact set of signers is determined. Once the parameters of the signing session are finalized, the signers can send partial signatures without additional interaction.
* **Partial signature independent of order**: The output of the signing algorithm remains consistent regardless of the order in which participant identifiers and public shares are used during the session context initialization. This property is inherent when combining Shamir shares to derive any value.
* **Third-party nonce and partial signature aggregation**: Instead of every signer sending their nonce and partial signature to every other signer, it is possible to use an untrusted third-party _aggregator_ in order to reduce the communication complexity from quadratic to linear in the number of signers. In each of the two rounds, the aggregator collects all signers' contributions (nonces or partial signatures), aggregates them, and broadcasts the aggregate back to the signers. A malicious aggregator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme.
* **Partial signature verification**: If any signer sends a partial signature contribution that was not created by honestly following the signing protocol, the signing session will fail to produce a valid Schnorr signature. This proposal specifies a partial signature verification algorithm to identify disruptive signers. It is incompatible with third-party nonce aggregation because the individual nonce is required for partial verification.
* **Size of the nonce**: In the FROST3 variant, each signer's nonce consists of two elliptic curve points.

## Overview

Implementers must make sure to understand this section thoroughly to avoid subtle mistakes that may lead to catastrophic failure.

### Optionality of Features

The goal of this proposal is to support a wide range of possible application scenarios.
Given a specific application scenario, some features may be unnecessary or not desirable, and implementers can choose not to support them.
Such optional features include:
- Applying plain tweaks after x-only tweaks.
- Applying tweaks at all.
- Dealing with messages that are not exactly 32 bytes.
- Identifying a disruptive signer after aborting (aborting itself remains mandatory).
If applicable, the corresponding algorithms should simply fail when encountering inputs unsupported by a particular implementation. (For example, the signing algorithm may fail when given a message which is not 32 bytes.)
Similarly, the test vectors that exercise the unimplemented features should be re-interpreted to expect an error, or be skipped if appropriate.

### Key Generation

We distinguish between two public key types, namely _plain public keys_, the key type traditionally used in Bitcoin, and _X-only public keys_.
Plain public keys are byte strings of length 33 (often called _compressed_ format).
In contrast, X-only public keys are 32-byte strings defined in [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

FROST generates signatures that are verifiable as if produced by a single signer using a secret key _s_ with the corresponding public key. As a threshold signing protocol, the group secret key _s_ is shared among all _MAX_PARTICIPANTS_ participants using Shamir's secret sharing, and at least _MIN_PARTICIPANTS_ participants must collaborate to issue a valid signature.
<!-- REVIEW should we make MIN_PARTICIPANTS at least 2   -->
&emsp;&ensp;_MIN_PARTICIPANTS_ is a positive non-zero integer lesser than or equal to _MAX_PARTICIPANTS_
&emsp;&ensp;_MAX_PARTICIPANTS_ MUST be a positive integer lesser than the 2^32.

In particular, FROST signing assumes each participant is configured with the following information:
- An identifier _id_, which is an integer in the range _[0, MAX_PARTICIPANTS - 1]_ and MUST be distinct from the identifier of every other participant.
<!-- REVIEW we haven't introduced participant identifier yet. So, don't use them here   -->
- A secret share _secshare<sub>id</sub>_, which is a positive non-zero integer lesser than the secp256k1 curve order. This value represents the _i_-th Shamir secret share of the group secret key _s_.  In particular, _secshare<sub>id</sub>_ is the value _f(id + 1)_ on a secret polynomial _f_ of degree _(MIN_PARTICIPANTS - 1)_, where _s_ is _f(0)_.
- A Group public key _group_pk_, which is point on the secp256k1 curve.
- A public share _pubshare<sub>id</sub>_, which is point on the secp256k1 curve.

> [!NOTE]
>  The definitions for the secp256k1 curve and its order can be found in the [Notation section](./README.md#notation).

As key generation for FROST signing is beyond the scope of this document, we do not specify how this information is configured and distributed to the participants. Generally, there are two possible key generation mechanisms: one involves a single, trusted dealer (see Appendix D of [FROST RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/)), and the other requires performing a distributed key generation protocol (see [BIP FROST DKG draft](https://github.com/BlockstreamResearch/bip-frost-dkg)).

For a key generation mechanism to be compatible with FROST signing, the participant information it generates MUST successfully pass both the _ValidateGroupPubkey_ and _ValidatePubshares_ functions (see [Key Generation Compatibility](./README.md#key-generation-compatibility)).

> [!IMPORTANT]
> It should be noted that while passing these functions ensures functional compatibility, it does not guarantee the security of the key generation mechanism.

### General Signing Flow

FROST signing is designed to be executed by a predetermined number of signer participants, referred to as _NUM_PARTICIPANTS_. This value is a positive non-zero integer that MUST be at least _MIN_PARTICIPANTS_ and MUST NOT exceed _MAX_PARTICIPANTS_. Therefore, the selection of signing participants from the participant group must be performed outside the signing protocol, prior to its initiation.

Whenever the signing participants want to sign a message, the basic order of operations to create a threshold-signature is as follows:

**First broadcast round:**
The signers start the signing session by running _NonceGen_ to compute _secnonce_ and _pubnonce_.[^nonce-serialization-detail]
Then, the signers broadcast their _pubnonce_ to each other and run _NonceAgg_ to compute an aggregate nonce.

**Second broadcast round:**
At this point, every signer has the required data to sign, which, in the algorithms specified below, is stored in a data structure called [Session Context](./README.md#session-context).
Every signer computes a partial signature by running _Sign_ with the participant identifier, the secret share, the _secnonce_ and the session context.
Then, the signers broadcast their partial signatures to each other and run _PartialSigAgg_ to obtain the final signature.
If all signers behaved honestly, the result passes [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) verification.

Both broadcast rounds can be optimized by using an aggregator who collects all signers' nonces or partial signatures, aggregates them using _NonceAgg_ or _PartialSigAgg_, respectively, and broadcasts the aggregate result back to the signers. A malicious aggregator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme, i.e., even a malicious aggregator colluding with all but one signer cannot forge a signature.

> [!IMPORTANT]
> The _Sign_ algorithm must **not** be executed twice with the same _secnonce_.
> Otherwise, it is possible to extract the secret signing key from the two partial signatures output by the two executions of _Sign_.
> To avoid accidental reuse of _secnonce_, an implementation may securely erase the _secnonce_ argument by overwriting it with 64 zero bytes after it has been read by _Sign_.
> A _secnonce_ consisting of only zero bytes is invalid for _Sign_ and will cause it to fail.

To simplify the specification of the algorithms, some intermediary values are unnecessarily recomputed from scratch, e.g., when executing _GetSessionValues_ multiple times.
Actual implementations can cache these values.
As a result, the [Session Context](./README.md#session-context) may look very different in implementations or may not exist at all.
However, computation of _GetSessionValues_ and storage of the result must be protected against modification from an untrusted third party.
This party would have complete control over the aggregate public key and message to be signed.

### Nonce Generation

> [!IMPORTANT]
> _NonceGen_ must have access to a high-quality random generator to draw an unbiased, uniformly random value _rand'_.
> In contrast to BIP340 signing, the values _k<sub>1</sub>_ and _k<sub>2</sub>_ **must not be derived deterministically** from the session parameters because deriving nonces deterministically allows for a [complete key-recovery attack in multi-party discrete logarithm-based signatures](https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6).

The optional arguments to _NonceGen_ enable a defense-in-depth mechanism that may prevent secret share exposure if _rand'_ is accidentally not drawn uniformly at random.
If the value _rand'_ was identical in two _NonceGen_ invocations, but any other argument was different, the _secnonce_ would still be guaranteed to be different as well (with overwhelming probability), and thus accidentally using the same _secnonce_ for _Sign_ in both sessions would be avoided.
Therefore, it is recommended to provide the optional arguments _secshare_, _pubshare_, _group_pk_, and _m_ if these session parameters are already determined during nonce generation.
The auxiliary input _extra_in_ can contain additional contextual data that has a chance of changing between _NonceGen_ runs,
e.g., a supposedly unique session id (taken from the application), a session counter wide enough not to repeat in practice, any nonces by other signers (if already known), or the serialization of a data structure containing multiple of the above.
However, the protection provided by the optional arguments should only be viewed as a last resort.
In most conceivable scenarios, the assumption that the arguments are different between two executions of _NonceGen_ is relatively strong, particularly when facing an active adversary.

In some applications, it is beneficial to generate and send a _pubnonce_ before the other signers, their _pubshare_, or the message to sign is known.
In this case, only the available arguments are provided to the _NonceGen_ algorithm.
After this preprocessing phase, the _Sign_ algorithm can be run immediately when the message and set of signers is determined.
This way, the final signature is created quicker and with fewer round trips.
However, applications that use this method presumably store the nonces for a longer time and must therefore be even more careful not to reuse them.
Moreover, this method is not compatible with the defense-in-depth mechanism described in the previous paragraph.

Instead of every signer broadcasting their _pubnonce_ to every other signer, the signers can send their _pubnonce_ to a single aggregator node that runs _NonceAgg_ and sends the _aggnonce_ back to the signers.
This technique reduces the overall communication.
A malicious aggregator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme.

In general, FROST signers are stateful in the sense that they first generate _secnonce_ and then need to store it until they receive the other signers' _pubnonces_ or the _aggnonce_.
However, it is possible for one of the signers to be stateless.
This signer waits until it receives the _pubnonce_ of all the other signers and until session parameters such as a message to sign, participant identifiers, participant public shares, and tweaks are determined.
Then, the signer can run _NonceGen_, _NonceAgg_ and _Sign_ in sequence and send out its _pubnonce_ along with its partial signature.
Stateless signers may want to consider signing deterministically (see [Modifications to Nonce Generation](./README.md#modifications-to-nonce-generation)) to remove the reliance on the random number generator in the _NonceGen_ algorithm.

### Identifying Disruptive Signers

The signing protocol makes it possible to identify malicious signers who send invalid contributions to a signing session in order to make the signing session abort and prevent the honest signers from obtaining a valid signature.
This property is called "identifiable aborts" and ensures that honest parties can assign blame to malicious signers who cause an abort in the signing protocol.

Aborts are identifiable for an honest party if the following conditions hold in a signing session:
- The contributions received from all signers have not been tampered with (e.g., because they were sent over authenticated connections).
- Nonce aggregation is performed honestly (e.g., because the honest signer performs nonce aggregation on its own or because the aggregator is trusted).
- The partial signatures received from all signers are verified using the algorithm _PartialSigVerify_.

If these conditions hold and an honest party (signer or aggregator) runs an algorithm that fails due to invalid protocol contributions from malicious signers, then the algorithm run by the honest party will output the participant identifier of exactly one malicious signer.
Additionally, if the honest parties agree on the contributions sent by all signers in the signing session, all the honest parties who run the aborting algorithm will identify the same malicious signer.

#### Further Remarks

Some of the algorithms specified below may also assign blame to a malicious aggregator.
While this is possible for some particular misbehavior of the aggregator, it is not guaranteed that a malicious aggregator can be identified.
More specifically, a malicious aggregator (whose existence violates the second condition above) can always make signing abort and wrongly hold honest signers accountable for the abort (e.g., by claiming to have received an invalid contribution from a particular honest signer).

The only purpose of the algorithm _PartialSigVerify_ is to ensure identifiable aborts, and it is not necessary to use it when identifiable aborts are not desired.
In particular, partial signatures are _not_ signatures.
An adversary can forge a partial signature, i.e., create a partial signature without knowing the secret share for that particular participant public share.[^partialsig-forgery]
However, if _PartialSigVerify_ succeeds for all partial signatures then _PartialSigAgg_ will return a valid Schnorr signature.


### Tweaking the Group Public Key

The group public key can be _tweaked_, which modifies the key as defined in the [Tweaking Definition](./README.md#tweaking-definition) subsection.
In order to apply a tweak, the Tweak Context output by _TweakCtxInit_ is provided to the _ApplyTweak_ algorithm with the _is_xonly_t_ argument set to false for plain tweaking and true for X-only tweaking.
The resulting Tweak Context can be used to apply another tweak with _ApplyTweak_ or obtain the group public key with _GetXonlyPubkey_ or _GetPlainPubkey_.

The purpose of supporting tweaking is to ensure compatibility with existing uses of tweaking, i.e., that the result of signing is a valid signature for the tweaked public key.
The FROST signing algorithms take arbitrary tweaks as input but accepting arbitrary tweaks may negatively affect the security of the scheme.[^arbitrary-tweaks]
Instead, signers should obtain the tweaks according to other specifications.
This typically involves deriving the tweaks from a hash of the aggregate public key and some other information.
Depending on the specific scheme that is used for tweaking, either the plain or the X-only aggregate public key is required.
For example, to do [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) derivation, you call _GetPlainPubkey_ to be able to compute the tweak, whereas [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) TapTweaks require X-only public keys that are obtained with _GetXonlyPubkey_.

The tweak mode provided to _ApplyTweak_ depends on the application:
Plain tweaking can be used to derive child public keys from an aggregate public key using [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
On the other hand, X-only tweaking is required for Taproot tweaking per [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
A Taproot-tweaked public key commits to a _script path_, allowing users to create transaction outputs that are spendable either with a FROST threshold-signature or by providing inputs that satisfy the script path.
Script path spends require a control block that contains a parity bit for the tweaked X-only public key.
The bit can be obtained with _GetPlainPubkey(tweak_ctx)[0] & 1_.

## Algorithms

The following specification of the algorithms has been written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation and space. In particular, some values are recomputed but can be cached in actual implementations (see [General Signing Flow](./README.md#general-signing-flow)).

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
    - The function _lift_x(x)_, where _x_ is an integer in range _0..2<sup>256</sup>-1_, returns the point _P_ for which _x(P) = x_[^liftx-soln] and _has_even_y(P)_, or fails if _x_ is greater than _p-1_ or no such point exists. The function _lift_x(x)_ is equivalent to the following pseudocode:
		- Fail if _x > p-1_.
		- Let _c = x<sup>3</sup> + 7 mod p_.
		- Let _y' = c<sup>(p+1)/4</sup> mod p_.
		- Fail if _c ≠ y'<sup>2</sup> mod p_.
		 - Let _y = y'_ if _y' mod 2 = 0_, otherwise let _y = p - y'_ .
		- Return the unique point _P_ such that _x(P) = x_ and _y(P) = y_.
    - The function _cpoint(x)_, where _x_ is a 33-byte array (compressed serialization), sets _P = lift_x(int(x[1:33]))_ and fails if that fails. If _x[0] = 2_ it returns _P_ and if _x[0] = 3_ it returns _-P_. Otherwise, it fails.
    - The function _cpoint_ext(x)_, where _x_ is a 33-byte array (compressed serialization), returns the point at infinity if _x = bytes(33, 0)_. Otherwise, it returns _cpoint(x)_ and fails if that fails.
    - The function _hash<sub>tag</sub>(x)_ where _tag_ is a UTF-8 encoded tag name and _x_ is a byte array returns the 32-byte hash _SHA256(SHA256(tag) || SHA256(tag) || x)_.
    - The function _count(lst, x)_, where _lst_ is a list of integers containing _x_, returns the number of times _x_ appears in _lst_.
    - The function _has_unique_elements(lst)_, where _lst_ is a list of integers, returns True if _count(lst, x)_ returns 1 for all _x_ in _lst_. Otherwise returns False. The function _has_unique_elements(lst)_ is equivalent to the following pseudocode:
        - For _x_ in _lst_:
          - if _count(lst, x)_ > 1:
            - Return False
        - Return True
    - The function _sorted(lst)_, where _lst_ is a list of integers, returns a new list of integers in ascending order.
- Other:
    - Tuples are written by listing the elements within parentheses and separated by commas. For example, _(2, 3, 1)_ is a tuple.

### Key Generation Compatibility

Internal Algorithm _PlainPubkeyGen(sk):_[^pubkey-gen-ecdsa]
- Input:
    - The secret key _sk_: a 32-byte array, freshly generated uniformly at random
- Let _d' = int(sk)_.
- Fail if _d' = 0_ or _d' &ge; n_.
- Return _cbytes(d'⋅G)_.
<!-- REVIEW maybe write scripts to automate these italics (math symbols)? -->
Algorithm _ValidatePubshares(secshare<sub>1..u</sub>, pubshare<sub>1..u</sub>)_
- Inputs:
    - The number _u_ of participants involved in keygen with 0 < _u_ < 2^32
    - The participant secret shares _secshare<sub>1..u</sub>_: _u_ 32-byte arrays
    - The corresponding public shares _pubshare<sub>1..u</sub>_: _u_ 33-byte arrays
- For _i = 1 .. u_:
    - Fail if _PlainPubkeyGen(secshare<sub>i</sub>)_ ≠ _pubshare<sub>i</sub>_
- Return success iff no failure occurred before reaching this point.

Algorithm _ValidateGroupPubkey(threshold, group_pk, id<sub>1..u</sub>, pubshare<sub>1..u</sub>)_:
- Inputs:
    - The number _u_ of participants involved in keygen with 0 < _u_ < 2^32
    - The number _threshold_ of participants required to issue a signature: an integer equal to _min_participants_
    - The group public key _group_pk_: a 33-byte array
    - The participant identifiers _id<sub>1..u</sub>_: _u_ integers, each with 0 ≤ _id<sub>i</sub>_ < _max_participants_
    - The participant public shares _pubshares<sub>1..u</sub>_: _u_ 33-byte arrays
- Fail if _threshold_ > _u_
- For _t_ = _threshold..u_:
    - For each combination of _t_ elements from _id<sub>1..u</sub>_:[^itertools-combinations]
        - Let _signer_id<sub>1..t</sub>_ be the current combination of participant identifiers
        - Let _signer_pubshare<sub>1..t</sub>_ be their corresponding participant pubshares[^calc-signer-pubshares]
        - _expected_pk_ = _DeriveGroupPubkey(signer_id<sub>1..t</sub>, signer_pubshare<sub>1..t</sub>)_
        - Fail if _group_pk_ ≠ _expected_pk_
- Return success iff no failure occurred before reaching this point.

### Key Derivation and Tweaking

#### Tweak Context

The Tweak Context is a data structure consisting of the following elements:
- The point _Q_ representing the potentially tweaked group public key: an elliptic curve point
- The accumulated tweak _tacc_: an integer with _0 ≤ tacc < n_
- The value _gacc_: 1 or -1 mod n

We write "Let _(Q, gacc, tacc) = tweak_ctx_" to assign names to the elements of a Tweak Context.

Algorithm _TweakCtxInit(id<sub>1..u</sub>, pubshare<sub>1..u</sub>):_
- Input:
    - The number _u_ of participants available in the signing session with _min_participants ≤ u ≤ max_participants_
    - The participant identifiers of the signers _id<sub>1..u</sub>_: _u_ integers, each with 0 ≤ _id<sub>i</sub>_ < _max_participants_
	- The individual public shares _pubshare<sub>1..u</sub>_: _u_ 33-byte arrays
- Let _group_pk = DeriveGroupPubkey(id<sub>1..u</sub>, pubshare<sub>1..u</sub>)_; fail if that fails
- Let _Q = cpoint(group_pk)_
- Fail if _is_infinite(Q)_.
- Let _gacc = 1_
- Let _tacc = 0_
- Return _tweak_ctx = (Q, gacc, tacc)_.

Internal Algorithm _DeriveGroupPubkey(id<sub>1..u</sub>, pubshare<sub>1..u</sub>)_
- _inf_point = bytes(33, 0)_
- _Q_ = _cpoint_ext(inf_point)_
- For _i_ = _1..u_:
    - _P_ = _cpoint(pubshare<sub>i</sub>)_; fail if that fails
    - _lambda_ = _DeriveInterpolatingValue(id<sub>1..u</sub>, id<sub>i</sub>)_
    - _Q_ = _Q_ + _lambda⋅P_
- Return _cbytes(Q)_

Internal Algorithm _DeriveInterpolatingValue(id<sub>1..u</sub>, my_id):_
- Fail if _my_id_ not in _id<sub>1..u</sub>_
- Fail if not _has_unique_elements(id<sub>1..u</sub>)_
- Let _num = 1_
- Let _denom = 1_
- For _i = 1..u_:
    - If _id<sub>i</sub>_ ≠ _my_id_:
	    - Let _num_ = _num⋅(id<sub>i</sub>_ + 1)
	    - Let _denom_ = _denom⋅(id<sub>i</sub> - my_id)_
- _lambda_ = _num⋅denom<sup>-1</sup> mod n_
- Return _lambda_

Algorithm _GetXonlyPubkey(tweak_ctx)_:
- Let _(Q, _, _) = tweak_ctx_
- Return _xbytes(Q)_

Algorithm _GetPlainPubkey(tweak_ctx)_:
- Let _(Q, _, _) = tweak_ctx_
- Return _cbytes(Q)_

#### Applying Tweaks

Algorithm _ApplyTweak(tweak_ctx, tweak, is_xonly_t)_:
- Inputs:
    - The _tweak_ctx_: a [Tweak Context](./README.md#tweak-context) data structure
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

Algorithm _NonceGen(secshare, pubshare, group_pk, m, extra_in)_:
- Inputs:
    - The participant’s secret share _secshare_: a 32-byte array (optional argument)
    - The corresponding public share _pubshare_: a 33-byte array (optional argument)
    - The x-only group public key _group_pk_: a 32-byte array (optional argument)
    - The message _m_: a byte array (optional argument)[^max-msg-len]
    - The auxiliary input _extra_in_: a byte array with _0 ≤ len(extra_in) ≤ 2<sup>32</sup>-1_ (optional argument)
- Let _rand'_ be a 32-byte array freshly drawn uniformly at random
- If the optional argument _secshare_ is present:
    - Let _rand_ be the byte-wise xor of _secshare_ and _hash<sub>FROST/aux</sub>(rand')_[^sk-xor-rand]
- Else:
    - Let _rand = rand'_
- If the optional argument _pubshare_ is not present:
    - Let _pubshare_ = _empty_bytestring_
- If the optional argument _group_pk_ is not present:
    - Let _group_pk_ = _empty_bytestring_
- If the optional argument _m_ is not present:
    - Let _m_prefixed = bytes(1, 0)_
- Else:
    - Let _m_prefixed = bytes(1, 1) || bytes(8, len(m)) || m_
- If the optional argument _extra_in_ is not present:
    - Let _extra_in = empty_bytestring_
- Let _k<sub>i</sub> = int(hash<sub>FROST/nonce</sub>(rand || bytes(1, len(pubshare)) || pubshare || bytes(1, len(group_pk)) || group_pk || m_prefixed || bytes(4, len(extra_in)) || extra_in || bytes(1, i - 1))) mod n_ for _i = 1,2_
- Fail if _k<sub>1</sub> = 0_ or _k<sub>2</sub> = 0_
- Let _R<sub>⁎,1</sub> = k<sub>1</sub>⋅G, R<sub>⁎,2</sub> = k<sub>2</sub>⋅G_
- Let _pubnonce = cbytes(R<sub>,1</sub>) || cbytes(R<sub>⁎,2</sub>)_
- Let _secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)_[^secnonce-ser]
- Return _(secnonce, pubnonce)_

### Nonce Aggregation

Algorithm _NonceAgg(pubnonce<sub>1..u</sub>, id<sub>1..u</sub>)_:
- Inputs:
    - The number of signers _u_: an integer with _min_participants ≤ u ≤ max_participants_
    - The public nonces _pubnonce<sub>1..u</sub>_: _u_ 66-byte arrays
    - The participant identifiers _id<sub>1..u</sub>_: _u_ integers, each with 0 ≤ _id<sub>i</sub>_ < _max_participants_
- For _j = 1 .. 2_:
    - For _i = 1 .. u_:
        - Let _R<sub>i,j</sub> = cpoint(pubnonce<sub>i</sub>[(j-1)_33:j_33])_; fail if that fails and blame signer _id<sub>i</sub>_ for invalid _pubnonce_.
    - Let _R<sub>j</sub> = R<sub>1,j</sub> + R<sub>2,j</sub> + ... + R<sub>u,j</sub>_
- Return _aggnonce = cbytes_ext(R<sub>1</sub>) || cbytes_ext(R<sub>2</sub>)_

### Session Context

The Session Context is a data structure consisting of the following elements:
- The number _u_ of participants available in the signing session with _min_participants ≤ u ≤ max_participants_
- The participant identifiers of the signers _id<sub>1..u</sub>_: _u_ integers, each with 0 ≤ _id<sub>i</sub>_ < _max_participants_
- The individual public shares _pubshare<sub>1..u</sub>_: _u_ 33-byte arrays
- The aggregate public nonce of signers _aggnonce_: a 66-byte array
- The number _v_ of tweaks with _0 ≤ v < 2^32_
- The tweaks _tweak<sub>1..v</sub>_: _v_ 32-byte arrays
- The tweak modes _is_xonly_t<sub>1..v</sub>_ : _v_ booleans
- The message _m_: a byte array[^max-msg-len]

We write "Let _(u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx_" to assign names to the elements of a Session Context.

Algorithm _GetSessionValues(session_ctx)_:
- Let _(u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx_
- Let _tweak_ctx<sub>0</sub> = TweakCtxInit(id<sub>1..u</sub>, pubshare<sub>1..u</sub>)_; fail if that fails
- For _i = 1 .. v_:
    - Let _tweak_ctx<sub>i</sub> = ApplyTweak(tweak_ctx<sub>i-1</sub>, tweak<sub>i</sub>, is_xonly_t<sub>i</sub>)_; fail if that fails
- Let _(Q, gacc, tacc) = tweak_ctx<sub>v</sub>_
- Let _ser_ids_ = _SerializeIds(id<sub>1..u</sub>)_
- Let b = _int(hash<sub>FROST/noncecoef</sub>(ser_ids || aggnonce || xbytes(Q) || m)) mod n_
- Let _R<sub>1</sub> = cpoint_ext(aggnonce[0:33]), R<sub>2</sub> = cpoint_ext(aggnonce[33:66])_; fail if that fails and blame nonce aggregator for invalid _aggnonce_.
- Let _R' = R<sub>1</sub> + b⋅R<sub>2</sub>_
- If _is_infinite(R'):_
    - _Let final nonce_ R = G _([see Dealing with Infinity in Nonce Aggregation](./README.md#dealing-with-infinity-in-nonce-aggregation))_
- _Else:_
    - _Let final nonce_ R = R'
- Let _e = int(hash<sub>BIP0340/challenge</sub>((xbytes(R) || xbytes(Q) || m))) mod n_
- _Return_ (Q, gacc, tacc, b, R, e)

Internal Algorithm _SerializeIds(id<sub>1..u</sub>)_:
- _res = empty_bytestring_
<!-- REVIEW should check for duplicates and id value range here? -->
- For _id_ in _sorted(id<sub>1..u</sub>)_:
  - _res = res || bytes(4, id)_
- Return _res_

Algorithm _GetSessionInterpolatingValue(session_ctx, my_id)_:
- Let _(u, id<sub>1..u</sub>, _, _, _, _, _) = session_ctx_
- Return _DeriveInterpolatingValue(id<sub>1..u</sub>, my_id)_; fail if that fails

Algorithm _SessionHasSignerPubshare(session_ctx, signer_pubshare)_:
- Let _(u, _, pubshare<sub>1..u</sub>, _, _, _, _) = session_ctx_
- If _signer_pubshare in pubshare<sub>1..u</sub>_
	- Return True
- Otherwise Return False

### Signing

Algorithm _Sign(secnonce, secshare, my_id, session_ctx)_:
- Inputs:
    - The secret nonce _secnonce_ that has never been used as input to _Sign_ before: a 64-byte array[^secnonce-ser]
    - The secret signing key _secshare_: a 32-byte array
    - The identifier of the signing participant _my_id_: an integer with 1 _≤ my_id < max_participants < 2^32_
    - The _session_ctx_: a [Session Context](./README.md#session-context) data structure
- Let _(Q, gacc, _, b, R, e) = GetSessionValues(session_ctx)_; fail if that fails
- Let _k<sub>1</sub>' = int(secnonce[0:32]), k<sub>2</sub>' = int(secnonce[32:64])_
- Fail if _k<sub>i</sub>' = 0_ or _k<sub>i</sub>' ≥ n_ for _i = 1..2_
- Let _k<sub>1</sub> = k<sub>1</sub>', k<sub>2</sub> = k<sub>2</sub>'_ if _has_even_y(R)_, otherwise let _k<sub>1</sub> = n - k<sub>1</sub>', k<sub>2</sub> = n - k<sub>2</sub>'_
- Let _d' = int(secshare)_
- Fail if _d' = 0_ or _d' ≥ n_
- Let _P = d'⋅G_
- Let _pubshare = cbytes(P)_
- Fail if _SessionHasSignerPubshare(session_ctx, pubshare) = False_
- Let _&lambda; = GetSessionInterpolatingValue(session_ctx, my_id)_; fail if that fails
- Let _g = 1_ if _has_even_y(Q)_, otherwise let _g = -1 mod n_
- Let _d = g⋅gacc⋅d' mod n_ (See [_Negation of Secret Share When Signing_](./README.md#negation-of-the-secret-share-when-signing))
- Let _s = (k<sub>1</sub> + b⋅k<sub>2</sub> + e⋅&lambda;⋅d) mod n_
- Let _psig = bytes(32, s)_
- Let _pubnonce = cbytes(k<sub>1</sub>'⋅G) || cbytes(k<sub>2</sub>'⋅G)_
- If _PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)_ (see below) returns failure, fail[^why-verify-partialsig]
- Return partial signature _psig_

### Partial Signature Verification

Algorithm _PartialSigVerify(psig, id<sub>1..u</sub>, pubnonce<sub>1..u</sub>, pubshare<sub>1..u</sub>, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m, i)_:
- Inputs:
    - The partial signature _psig_: a 32-byte array
    - The number _u_ of identifiers, public nonces, and individual public shares with _min_participants ≤ u ≤ max_participants_
    - The participant identifiers _id<sub>1..u</sub>_: _u_ integers, each with _0 ≤ id<sub>i</sub> < max_participants < 2^32_
    - The public nonces _pubnonce<sub>1..u</sub>_: _u_ 66-byte arrays
    - The individual public shares _pubshare<sub>1..u</sub>_: _u_ 33-byte arrays
    - The number _v_ of tweaks with _0 ≤ v < 2^32_
    - The tweaks _tweak<sub>1..v</sub>_: _v_ 32-byte arrays
    - The tweak modes _is_xonly_t<sub>1..v</sub>_ : _v_ booleans
    - The message _m_: a byte array[^max-msg-len]
    - The index _i_ of the signer in the list of identifiers, public nonces, and individual public shares where _0 < i ≤ u_
- Let _aggnonce = NonceAgg(pubnonce<sub>1..u</sub>)_; fail if that fails
- Let _session_ctx = (u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m)_
- Run _PartialSigVerifyInternal(psig, id<sub>i</sub>, pubnonce<sub>i</sub>, pubshare<sub>i</sub>, session_ctx)_
- Return success iff no failure occurred before reaching this point.

Internal Algorithm _PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)_:
- Let _(Q, gacc, _, b, R, e) = GetSessionValues(session_ctx)_; fail if that fails
- Let _s = int(psig)_; fail if _s ≥ n_
- Fail if _SessionHasSignerPubshare(session_ctx, pubshare) = False_
- Let _R<sub>⁎,1</sub> = cpoint(pubnonce[0:33]), R<sub>⁎,2</sub> = cpoint(pubnonce[33:66])_
- Let _Re<sub>⁎</sub>' = R<sub>⁎,1</sub> + b⋅R<sub>⁎,2</sub>_
- Let effective nonce _Re<sub>⁎</sub> = Re<sub>⁎</sub>'_ if _has_even_y(R)_, otherwise let _Re<sub>⁎</sub> = -Re<sub>⁎</sub>'_
- Let _P = cpoint(pubshare)_; fail if that fails
- Let _&lambda; = GetSessionInterpolatingValue(session_ctx, my_id)_[^lambda-cant-fail]
- Let _g = 1_ if _has_even_y(Q)_, otherwise let _g = -1 mod n_
- Let _g' = g⋅gacc mod n_ (See [_Negation of Pubshare When Partially Verifying_](./README.md#negation-of-the-pubshare-when-partially-verifying))
- Fail if _s⋅G ≠ Re<sub>⁎</sub> + e⋅&lambda;⋅g'⋅P_
- Return success iff no failure occurred before reaching this point.

### Partial Signature Aggregation

Algorithm _PartialSigAgg(psig<sub>1..u</sub>, id<sub>1..u</sub>, session_ctx)_:
- Inputs:
    - The number _u_ of signatures with _min_participants ≤ u ≤ max_participants_
    - The partial signatures _psig<sub>1..u</sub>_: _u_ 32-byte arrays
    - The participant identifiers _id<sub>1..u</sub>_: _u_ integers, each with _0 ≤ id<sub>i</sub> < max_participants < 2^32_
    - The _session_ctx_: a [Session Context](./README.md#session-context) data structure
- Let _(Q, _, tacc, _, _, R, e) = GetSessionValues(session_ctx)_; fail if that fails
- For _i = 1 .. u_:
    - Let _s<sub>i</sub> = int(psig<sub>i</sub>)_; fail if _s<sub>i</sub> ≥ n_ and blame signer _id<sub>i</sub>_ for invalid partial signature.
- Let _g = 1_ if _has_even_y(Q)_, otherwise let _g = -1 mod n_
- Let _s = s<sub>1</sub> + ... + s<sub>u</sub> + e⋅g⋅tacc mod n_
- Return _sig =_ xbytes(R) || bytes(32, s)

### Test Vectors & Reference Code

We provide a naive, highly inefficient, and non-constant time [pure Python 3 reference implementation of the group public key tweaking, nonce generation, partial signing, and partial signature verification algorithms](./reference/reference.py).

Standalone JSON test vectors are also available in the [same directory](./reference/vectors/), to facilitate porting the test vectors into other implementations.

> [!CAUTION]
> The reference implementation is for demonstration purposes only and not to be used in production environments.

## Remarks on Security and Correctness

### Modifications to Nonce Generation

Implementers must avoid modifying the _NonceGen_ algorithm without being fully aware of the implications.
We provide two modifications to _NonceGen_ that are secure when applied correctly and may be useful in special circumstances, summarized in the following table.

|  | needs secure randomness | needs secure counter | needs to keep state securely | needs aggregate nonce of all other signers (only possible for one signer) |
| --- | --- | --- | --- | --- |
| **NonceGen** | ✓ |  | ✓ |  |
| **CounterNonceGen** |  | ✓ | ✓ |  |
| **DeterministicSign** |  |  |  | ✓ |

First, on systems where obtaining uniformly random values is much harder than maintaining a global atomic counter, it can be beneficial to modify _NonceGen_.
The resulting algorithm _CounterNonceGen_ does not draw _rand'_ uniformly at random but instead sets _rand'_ to the value of an atomic counter that is incremented whenever it is read.
With this modification, the secret share _secshare_ of the signer generating the nonce is **not** an optional argument and must be provided to _NonceGen_.
The security of the resulting scheme then depends on the requirement that reading the counter must never yield the same counter value in two _NonceGen_ invocations with the same _secshare_.

Second, if there is a unique signer who is supposed to send the _pubnonce_ last, it is possible to modify nonce generation for this single signer to not require high-quality randomness.
Such a nonce generation algorithm _DeterministicSign_ is specified below.
Note that the only optional argument is _rand_, which can be omitted if randomness is entirely unavailable.
_DeterministicSign_ requires the argument _aggothernonce_ which should be set to the output of _NonceAgg_ run on the _pubnonce_ value of **all** other signers (but can be provided by an untrusted party).
Hence, using _DeterministicSign_ is only possible for the last signer to generate a nonce and makes the signer stateless, similar to the stateless signer described in the [Nonce Generation](./README.md#nonce-generation) section.
<!-- REVIEW just say max_participants is < 2^32 during intro, than mentioning it everywhere -->
#### Deterministic and Stateless Signing for a Single Signer

Algorithm _DeterministicSign(secshare, my_id, aggothernonce, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m, rand)_:
- Inputs:
    - The secret share _secshare_: a 32-byte array
    - The identifier of the signing participant _my_id_: an integer with 0 _≤ my_id < max_participants < 2^32_
    - The aggregate public nonce _aggothernonce_ (see [above](./README.md#modifications-to-nonce-generation)): a 66-byte array
    - The number _u_ of identifiers and participant public shares with _min_participants ≤ u ≤ max_participants_
    - The participant identifiers _id<sub>1..u</sub>_: _u_ integers, each with _0 ≤ id<sub>i</sub> < max_participants < 2^32_
    - The individual public shares _pubshare<sub>1..u</sub>_: _u_ 33-byte arrays
    - The number _v_ of tweaks with _0 &le; v < 2^32_
    - The tweaks _tweak<sub>1..v</sub>_: _v_ 32-byte arrays
    - The tweak methods _is_xonly_t<sub>1..v</sub>_: _v_ booleans
    - The message _m_: a byte array[^max-msg-len]
    - The auxiliary randomness _rand_: a 32-byte array (optional argument)
- If the optional argument _rand_ is present:
    - Let _secshare'_ be the byte-wise xor of _secshare_ and _hash<sub>FROST/aux</sub>(rand)_
- Else:
    - Let _secshare' = secshare_
- Let _tweak_ctx<sub>0</sub> = TweakCtxInit(id<sub>1..u</sub>, pubshare<sub>1..u</sub>)_; fail if that fails
- For _i = 1 .. v_:
    - Let _tweak_ctx<sub>i</sub> = ApplyTweak(tweak_ctx<sub>i-1</sub>, tweak<sub>i</sub>, is_xonly_t<sub>i</sub>)_; fail if that fails
- Let _tweaked_gpk = GetXonlyPubkey(tweak_ctx<sub>v</sub>)_
- Let _k<sub>i</sub> = int(hash<sub>FROST/deterministic/nonce</sub>(secshare' || aggothernonce || tweaked_gpk || bytes(8, len(m)) || m || bytes(1, i - 1))) mod n_ for _i = 1,2_
- Fail if _k<sub>1</sub> = 0_ or _k<sub>2</sub> = 0_
- Let _R<sub>⁎,1</sub> = k<sub>1</sub>⋅G, R<sub>⁎,2</sub> = k<sub>2</sub>⋅G_
- Let _pubnonce = cbytes(R<sub>⁎,2</sub>) || cbytes(R<sub>⁎,2</sub>)_
- Let _d = int(secshare)_
- Fail if _d = 0_ or _d &ge; n_
- Let _signer_pubshare = cbytes(d⋅G)_
- Fail if _signer_pubshare_ is not present in _pubshare<sub>1..u</sub>_
- Let _secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)_
- Let _aggnonce = NonceAgg((pubnonce, aggothernonce))_; fail if that fails and blame nonce aggregator for invalid _aggothernonce_.
- Let _session_ctx = (u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m)_
- Return _(pubnonce, Sign(secnonce, secshare, my_id, session_ctx))_

### Tweaking Definition

Two modes of tweaking the group public key are supported. They correspond to the following algorithms:

Algorithm _ApplyPlainTweak(P, t)_:
- Inputs:
    - _P_: a point
    - The tweak _t_: an integer with _0 ≤ t < n_
- Return _P + t⋅G_

Algorithm _ApplyXonlyTweak(P, t)_:
- Return _with_even_y(P) + t⋅G_

### Negation of the Secret Share when Signing

During the signing process, the *[Sign](./README.md#signing)* algorithm might have to negate the secret share in order to produce a partial signature for an X-only group public key. This public key is derived from *u* public shares and *u* participant identifiers (denoted by the signer set *U*) and then tweaked *v* times (X-only or plain).

The following elliptic curve points arise as intermediate steps when creating a signature:  
• _P<sub>i</sub>_ as computed in any compatible key generation method is the point corresponding to the *i*-th signer's public share. Defining *d<sub>i</sub>'* to be the *i*-th signer's secret share as an integer, i.e., the *d’* value as computed in the *Sign* algorithm of the *i*-th signer, we have:  
&emsp;&ensp;*P<sub>i</sub> = d<sub>i</sub>'⋅G*  
• *Q<sub>0</sub>* is the group public key derived from the signer’s public shares. It is identical to the value *Q* computed in *DeriveGroupPubkey* and therefore defined as:  
&emsp;&ensp;_Q<sub>0</sub> = &lambda;<sub>1, U</sub>⋅P<sub>1</sub> + &lambda;<sub>2, U</sub>⋅P<sub>2</sub> + ... + &lambda;<sub>u, U</sub>⋅P<sub>u</sub>_  
• *Q<sub>i</sub>* is the tweaked group public key after the *i*-th execution of *ApplyTweak* for *1 ≤ i ≤ v*. It holds that  
&emsp;&ensp;*Q<sub>i</sub> = f(i-1) + t<sub>i</sub>⋅G* for *i = 1, ..., v* where  
&emsp;&ensp;&emsp;&ensp;*f(i-1) := with_even_y(Q<sub>i-1</sub>)* if *is_xonly_t<sub>i</sub>* and  
&emsp;&ensp;&emsp;&ensp;*f(i-1) := Q<sub>i-1</sub>* otherwise.  
• *with_even_y(Q*<sub>v</sub>*)* is the final result of the group public key derivation and tweaking operations. It corresponds to the output of *GetXonlyPubkey* applied on the final Tweak Context.

The signer's goal is to produce a partial signature corresponding to the final result of group pubkey derivation and tweaking, i.e., the X-only public key *with_even_y(Q<sub>v</sub>)*.

For _1 ≤ i ≤ v_, we denote the value _g_ computed in the _i_-th execution of _ApplyTweak_ by _g<sub>i-1</sub>_. Therefore, _g<sub>i-1</sub>_ is _-1 mod n_ if and only if _is_xonly_t<sub>i</sub>_ is true and _Q<sub>i-1</sub>_ has an odd Y coordinate. In other words, _g<sub>i-1</sub>_ indicates whether _Q<sub>i-1</sub>_ needed to be negated to apply an X-only tweak:  
&emsp;&ensp;_f(i-1) = g<sub>i-1</sub>⋅Q<sub>i-1</sub>_ for _1 ≤ i ≤ v_.  
Furthermore, the _Sign_ and _PartialSigVerify_ algorithms set value _g_ depending on whether Q<sub>v</sub> needed to be negated to produce the (X-only) final output. For consistency, this value _g_ is referred to as _g<sub>v</sub>_ in this section.  
&emsp;&ensp;_with_even_y(Q<sub>v</sub>) = g<sub>v</sub>⋅Q<sub>v</sub>_.

So, the (X-only) final public key is  
&emsp;&ensp;_with_even_y(Q<sub>v</sub>)_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅Q<sub>v</sub>_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅(f(v-1)_ + _t<sub>v</sub>⋅G)_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅(g<sub>v-1</sub>⋅(f(v-2)_ + _t<sub>v-1</sub>⋅G)_ + _t<sub>v</sub>⋅G)_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅g<sub>v-1</sub>⋅f(v-2)_ + _g<sub>v</sub>⋅(t<sub>v</sub>_ + _g<sub>v-1</sub>⋅t<sub>v-1</sub>)⋅G_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅g<sub>v-1</sub>⋅f(v-2)_ + _(sum<sub>i=v-1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>)⋅G_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅g<sub>v-1</sub>⋅...⋅g<sub>1</sub>⋅f(0)_ + _(sum<sub>i=1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>)⋅G_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅...⋅g<sub>0</sub>⋅Q<sub>0</sub>_ + _g<sub>v</sub>⋅tacc<sub>v</sub>⋅G_   
&emsp;&ensp;where _tacc<sub>i</sub>_ is computed by _TweakCtxInit_ and _ApplyTweak_ as follows:  
&emsp;&ensp;&emsp;&ensp;_tacc<sub>0</sub>_ = _0_  
&emsp;&ensp;&emsp;&ensp;_tacc<sub>i</sub>_ = _t<sub>i</sub>_ + _g<sub>i-1</sub>⋅tacc<sub>i-1</sub> for i=1..v mod n_  
&emsp;&ensp;for which it holds that _g<sub>v</sub>⋅tacc<sub>v</sub>_ = _sum<sub>i=1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>_.

_TweakCtxInit_ and _ApplyTweak_ compute  
&emsp;&ensp;_gacc<sub>0</sub>_ = 1  
&emsp;&ensp;_gacc<sub>i</sub>_ = _g<sub>i-1</sub>⋅gacc<sub>i-1</sub> for i=1..v mod n_  
So we can rewrite above equation for the final public key as  
&emsp;&ensp;_with_even_y(Q<sub>v</sub>)_ = _g<sub>v</sub>⋅gacc<sub>v</sub>⋅Q<sub>0</sub>_ + _g<sub>v</sub>⋅tacc<sub>v</sub>⋅G._

Then we have  
&emsp;&ensp;_with_even_y(Q<sub>v</sub>)_ - _g<sub>v</sub>⋅tacc<sub>v</sub>⋅G_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅gacc<sub>v</sub>⋅Q<sub>0</sub>_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅gacc<sub>v</sub>⋅(&lambda;<sub>1, U</sub>⋅P<sub>1</sub> + ... + &lambda;<sub>u, U</sub>⋅P<sub>u</sub>)_  
&emsp;&ensp;&emsp;&ensp;= _g<sub>v</sub>⋅gacc<sub>v</sub>⋅(&lambda;<sub>1, U</sub>⋅d<sub>1</sub>'⋅G + ... + &lambda;<sub>u, U</sub>⋅d<sub>u</sub>'⋅G)_  
&emsp;&ensp;&emsp;&ensp;= _sum<sub>i=1..u</sub>(g<sub>v</sub>⋅gacc<sub>v</sub>⋅&lambda;<sub>i, U</sub>⋅d<sub>i</sub>')*G._  

Intuitively, _gacc<sub>i</sub>_ tracks accumulated sign flipping and _tacc<sub>i</sub>_ tracks the accumulated tweak value after applying the first _i_ individual tweaks. Additionally, _g<sub>v</sub>_ indicates whether _Q<sub>v</sub>_ needed to be negated to produce the final X-only result. Thus, signer _i_ multiplies its secret share _d<sub>i</sub>'_ with _g<sub>v</sub>⋅gacc<sub>v</sub>_ in the [_Sign_](./README.md#signing) algorithm.

#### Negation of the Pubshare when Partially Verifying

As explained in [Negation Of The Secret Share When Signing](./README.md#negation-of-the-secret-share-when-signing) the signer uses a possibly negated secret share  
&emsp;&ensp;_d = g<sub>v</sub>⋅gacc<sub>v</sub>⋅d' mod n_  
when producing a partial signature to ensure that the aggregate signature will correspond to a group public key with even Y coordinate.

The [_PartialSigVerifyInternal_](./README.md#partial-signature-verification) algorithm is supposed to check  
&emsp;&ensp;_s⋅G = Re<sub>⁎</sub> + e⋅&lambda;⋅d⋅G_.

The verifier doesn't have access to _d⋅G_ but can construct it using the participant public share _pubshare_ as follows:  
_d⋅G  
&emsp;&ensp;= g<sub>v</sub>⋅gacc<sub>v</sub>⋅d'⋅G  
&emsp;&ensp;= g<sub>v</sub>⋅gacc<sub>v</sub>⋅cpoint(pubshare)_  
Note that the group public key and list of tweaks are inputs to partial signature verification, so the verifier can also construct _g<sub>v</sub>_ and _gacc<sub>v</sub>_.

### Dealing with Infinity in Nonce Aggregation

If the nonce aggregator provides _aggnonce = bytes(33,0) || bytes(33,0)_, either the nonce aggregator is dishonest or there is at least one dishonest signer (except with negligible probability).
If signing aborted in this case, it would be impossible to determine who is dishonest.
Therefore, signing continues so that the culprit is revealed when collecting and verifying partial signatures.

However, the final nonce _R_ of a BIP340 Schnorr signature cannot be the point at infinity.
If we would nonetheless allow the final nonce to be the point at infinity, then the scheme would lose the following property:
if _PartialSigVerify_ succeeds for all partial signatures, then _PartialSigAgg_ will return a valid Schnorr signature.
Since this is a valuable feature, we modify FROST3 (which is defined in the section 2.3 of the [ROAST paper](https://eprint.iacr.org/2022/550.pdf)) to avoid producing an invalid Schnorr signature while still allowing detection of the dishonest signer: In _GetSessionValues_, if the final nonce _R_ would be the point at infinity, set it to the generator instead (an arbitrary choice).

This modification to _GetSessionValues_ does not affect the unforgeability of the scheme.
Given a successful adversary against the unforgeability game (EUF-CMA) for the modified scheme, a reduction can win the unforgeability game for the original scheme by simulating the modification towards the adversary:
When the adversary provides _aggnonce' = bytes(33, 0) || bytes(33, 0)_, the reduction sets _aggnonce = cbytes_ext(G) || bytes(33, 0)_.
For any other _aggnonce'_, the reduction sets _aggnonce = aggnonce'_.
(The case that the adversary provides an _aggnonce' ≠ bytes(33, 0) || bytes(33, 0)_ but nevertheless _R'_ in _GetSessionValues_ is the point at infinity happens only with negligible probability.)

## Backwards Compatibility

This document proposes a standard for the FROST threshold signature scheme that is compatible with [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki). FROST is _not_ compatible with ECDSA signatures traditionally used in Bitcoin.

## Changelog

To help the reader understand updates to this document, we attach a version number that resembles "semantic versioning" (`MAJOR.MINOR.PATCH`).
The `MAJOR` version is incremented if changes to the BIP are introduced that are incompatible with prior versions.
An exception to this rule is `MAJOR` version zero (0.y.z) which is for development and does not need to be incremented if backwards-incompatible changes are introduced.
The `MINOR` version is incremented whenever the inputs or the output of an algorithm changes in a backward-compatible way or new backward-compatible functionality is added.
The `PATCH` version is incremented for other noteworthy changes (bug fixes, test vectors, important clarifications, etc.).

* *0.1.0* (2024-07-31): Publication of draft BIP on the bitcoin-dev mailing list

## Acknowledgments
<!-- Ordered alphabetically by last name -->
We thank Jesse Posner, Tim Ruffing, and Jonas Nick for their contributions to this document.

<!-- Footnotes -->

[^t-edge-cases]: While `t = n` and `t = 1` are in principle supported, simpler alternatives are available in these cases.
In the case `t = n`, using a dedicated `n`-of-`n` multi-signature scheme such as MuSig2 (see [BIP327](bip-0327.mediawiki)) instead of FROST avoids the need for an interactive DKG.
The case `t = 1` can be realized by letting one signer generate an ordinary [BIP340](bip-0340.mediawiki) key pair and transmitting the key pair to every other signer, who can check its consistency and then simply use the ordinary [BIP340](bip-0340.mediawiki) signing algorithm.
Signers still need to ensure that they agree on a key pair. A detailed specification for this key sharing protocol is not in the scope of this document.

[^nonce-serialization-detail]: We treat the _secnonce_ and _pubnonce_ as grammatically singular even though they include serializations of two scalars and two elliptic curve points, respectively. This treatment may be confusing for readers familiar with the MuSig2 paper. However, serialization is a technical detail that is irrelevant for users of MuSig2 interfaces.

[^pubkey-gen-ecdsa]: The _PlainPubkeyGen_ algorithm matches the key generation procedure traditionally used for ECDSA in Bitcoin

[^itertools-combinations]: This line represents a loop over every possible combination of `t` elements sourced from the `int_ids` array. This operation is equivalent to invoking the [`itertools.combinations(int_ids, t)`](https://docs.python.org/3/library/itertools.html#itertools.combinations) function call in Python.

[^calc-signer-pubshares]: This _signer_pubshare<sub>1..t</sub>_ list can be computed from the input _pubshare<sub>1..u</sub>_ list.  
Method 1 - use `itertools.combinations(zip(int_ids, pubshares), t)`  
Method 2 - For _i = 1..t_ :  signer_pubshare<sub>i</sub> = pubshare<sub>signer_id<sub>i</sub></sub>

[^arbitrary-tweaks]: It is an open question whether allowing arbitrary tweaks from an adversary affects the unforgeability of FROST.

[^partialsig-forgery]: Assume a malicious participant intends to forge a partial signature for the participant with public share _P_. It participates in the signing session pretending to be two distinct signers: one with the public share _P_ and the other with its own public share. The adversary then sets the nonce for the second signer in such a way that allows it to generate a partial signature for _P_. As a side effect, it cannot generate a valid partial signature for its own public share. An explanation of the steps required to create a partial signature forgery can be found in [this document](docs/partialsig_forgery.md).

[^liftx-soln]: Given a candidate X coordinate _x_ in the range _0..p-1_, there exist either exactly two or exactly zero valid Y coordinates. If no valid Y coordinate exists, then _x_ is not a valid X coordinate either, i.e., no point _P_ exists for which _x(P) = x_. The valid Y coordinates for a given candidate _x_ are the square roots of _c = x<sup>3</sup> + 7 mod p_ and they can be computed as _y = &plusmn;c<sup>(p+1)/4</sup> mod p_ (see [Quadratic residue](https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus)) if they exist, which can be checked by squaring and comparing with _c_.

[^max-msg-len]: In theory, the allowed message size is restricted because SHA256 accepts byte strings only up to size of 2^61-1 bytes (and because of the 8-byte length encoding).

[^sk-xor-rand]: The random data is hashed (with a unique tag) as a precaution against situations where the randomness may be correlated with the secret signing key itself. It is xored with the secret key (rather than combined with it in a hash) to reduce the number of operations exposed to the actual secret key.

[^secnonce-ser]: The algorithms as specified here assume that the _secnonce_ is stored as a 64-byte array using the serialization _secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)_. The same format is used in the reference implementation and in the test vectors. However, since the _secnonce_ is (obviously) not meant to be sent over the wire, compatibility between implementations is not a concern, and this method of storing the _secnonce_ is merely a suggestion.<br />
The _secnonce_ is effectively a local data structure of the signer which comprises the value triple _(k<sub>1</sub>, k<sub>2</sub>)_, and implementations may choose any suitable method to carry it from _NonceGen_ (first communication round) to _Sign_ (second communication round). In particular, implementations may choose to hide the _secnonce_ in internal state without exposing it in an API explicitly, e.g., in an effort to prevent callers from reusing a _secnonce_ accidentally.

[^why-verify-partialsig]: Verifying the signature before leaving the signer prevents random or adversarially provoked computation errors. This prevents publishing invalid signatures which may leak information about the secret key. It is recommended but can be omitted if the computation cost is prohibitive.

[^lambda-cant-fail]: _GetSessionInterpolatingValue(session_ctx, my_id)_ cannot fail when called from _PartialSigVerifyInternal_.

