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

This document proposes a standard for the Flexible Round-Optimized Schnorr Threshold (FROST) signing protocol. The standard is compatible with [BIP340][bip340] public keys and signatures. It supports *tweaking*, which allows deriving [BIP32][bip32] child keys from the threshold public key and creating [BIP341][bip341] Taproot outputs with key and script paths.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

This document proposes the FROST signing protocol based on the FROST3 variant (see section 2.3) introduced in ROAST[[RRJSS22][roast]], instead of the original FROST[[KG20][frost1]]. Key generation for FROST signing is out of scope for this document. However, we specify the requirements that a key generation method must satisfy to be compatible with this signing protocol.

Many sections of this document have been directly copied or modified from [BIP327][bip327] due to the similarities between the FROST3 and [MuSig2](https://eprint.iacr.org/2020/1261.pdf) signature schemes.

### Motivation
<!-- todo: this section seems direct copy of chilldkg. So update/change this to focus on the signing than key gen -->

The FROST signature scheme [[KG20][frost1],[CKM21][frost2],[BTZ21][stronger-security-frost],[CGRS23][olaf]] enables `t`-of-`n` Schnorr threshold signatures, in which a threshold `t` of some set of `n` signers is required to produce a signature.
FROST remains unforgeable as long as at most `t-1` signers are compromised, and remains functional as long as `t` honest signers do not lose their secret key material. It supports any choice of `t` as long as `1 <= t <= n`.[^t-edge-cases]

[^t-edge-cases]: While `t = n` and `t = 1` are in principle supported, simpler alternatives are available in these cases. In the case `t = n`, using a dedicated `n`-of-`n` multi-signature scheme such as MuSig2 (see [BIP327](bip-0327.mediawiki)) instead of FROST avoids the need for an interactive DKG. The case `t = 1` can be realized by letting one signer generate an ordinary [BIP340](bip-0340.mediawiki) key pair and transmitting the key pair to every other signer, who can check its consistency and then simply use the ordinary [BIP340](bip-0340.mediawiki) signing algorithm. Signers still need to ensure that they agree on a key pair.

The primary motivation is to create a standard that allows users of different software projects to jointly control Taproot outputs ([BIP341][bip341]).
Such an output contains a public key which, in this case, would be the threshold public key derived from the public shares of threshold signers.
It can be spent using FROST to produce a signature for the key-based spending path.

The on-chain footprint of a FROST Taproot output is essentially a single BIP340 public key, and a transaction spending the output only requires a single signature cooperatively produced by *threshold* signers. This is **more compact** and has **lower verification cost** than signers providing `n` individual public keys and `t` signatures, as would be required by an `t`-of-`n` policy implemented using `OP_CHECKSIGADD` as introduced in ([BIP342][bip342]).
As a side effect, the numbers `t` and `n` of signers are not limited by any consensus rules when using FROST.

Moreover, FROST offers a **higher level of privacy** than `OP_CHECKSIGADD`: FROST Taproot outputs are indistinguishable for a blockchain observer from regular, single-signer Taproot outputs even though they are actually controlled by multiple signers. By tweaking a threshold public key, the shared Taproot output can have script spending paths that are hidden unless used.

There are threshold-signature schemes other than FROST that are fully compatible with Schnorr signatures.
The FROST variant proposed below stands out by combining all the following features:
* **Two Communication Rounds**: FROST is faster in practice than other threshold-signature schemes [[GJKR03][thresh-with-dkg]] which requires at least three rounds, particularly when signers are connected through high-latency anonymous links. Moreover, the need for fewer communication rounds simplifies the algorithms and reduces the probability that implementations and users make security-relevant mistakes.
* **Efficiency over Robustness**: FROST trades off the robustness property for network efficiency (fewer communication rounds), requiring the protocol to be aborted in the case of any misbehaving participant.
<!--todo: the security is also proved for distributed setup right? mention that.
and also about the combination of security proofs. we can't randomly use combination. Don't mention it here. But somewhere else. -->
* **Provable security**: FROST3 with an idealized key generation (i.e., trusted setup) has been [proven existentially unforgeable](https://eprint.iacr.org/2022/550.pdf) under the one-more discrete logarithm (OMDL) assumption (instead of the discrete logarithm assumption required for single-signer Schnorr signatures) in the random oracle model (ROM).

### Design

* **Compatibility with BIP340**: The threshold public key and participant public shares produced by a compatible key generation algorithm MUST be *plain* public keys in compressed format. In this proposal, the signature output at the end of the signing protocol is a BIP340 signature, which passes BIP340 verification for the BIP340 X-only version of the threshold public key and a message.
* **Tweaking for BIP32 derivations and Taproot**: This proposal supports tweaking threshold public key and signing for this tweaked threshold public key. We distinguish two modes of tweaking: *Plain* tweaking can be used to derive child threshold public keys per [BIP32][bip32].*X-only* tweaking, on the other hand, allows creating a [BIP341][bip341] tweak to add script paths to a Taproot output. See [tweaking the threshold public key](./README.md#tweaking-threshold-public-key) below for details.
* **Non-interactive signing with preprocessing**: The first communication round, exchanging the nonces, can happen before the message or the exact set of signers is determined. Once the parameters of the signing session are finalized, the signers can send partial signatures without additional interaction.
* **Partial signature independent of order**: The output of the signing algorithm remains consistent regardless of the order in which participant identifiers and public shares are used during the session context initialization. This property is inherent when combining Shamir shares to derive any value.
* **Third-party nonce and partial signature aggregation**: Instead of every signer sending their nonce and partial signature to every other signer, it is possible to use an untrusted third-party *coordinator* to reduce the communication complexity from quadratic to linear in the number of signers. In each of the two rounds, the coordinator collects all signers' contributions (nonces or partial signatures), aggregates them, and broadcasts the aggregate back to the signers. A malicious coordinator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme.
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

We distinguish between two public key types, namely *plain public keys*, the key type traditionally used in Bitcoin, and *X-only public keys*.
Plain public keys are byte strings of length 33 (often called *compressed* format).
In contrast, X-only public keys are 32-byte strings defined in [BIP340][bip340].

FROST generates signatures that are verifiable as if produced by a single signer using a secret key `s` with the corresponding public key. As a threshold signing protocol, the threshold secret key `s` is shared among all `n` participants using Shamir's secret sharing, and at least `t` participants must collaborate to issue a valid signature.<br>
- `t` is a positive non-zero integer lesser than or equal to `n`<br>
- `n` MUST be a positive integer less than 2^32.

In particular, FROST signing assumes each participant is configured with the following information:<br>
- An identifier *id*, which is an integer in the range `[0, n-1]` and MUST be distinct from the identifier of every other participant.
<!-- REVIEW we haven't introduced participant identifier yet. So, don't use them here -->
- A secret share *secshare<sub>id</sub>*, which is a positive non-zero integer less than the secp256k1 curve order. This value represents the *i*-th Shamir secret share of the threshold secret key *s*. In particular, *secshare<sub>id</sub>* is the value `f(id+1)` on a secret polynomial `f` of degree `t - 1`, where `s` is `f(0)`.
- A Threshold public key *thresh_pk*, which is point on the secp256k1 curve.
- A public share *pubshare<sub>id</sub>*, which is point on the secp256k1 curve.

> [!NOTE]
> The definitions for the secp256k1 curve and its order can be found in the [Notation section](./README.md#notation).

As key generation for FROST signing is beyond the scope of this document, we do not specify how this information is configured and distributed to the participants. Generally, there are two possible key generation mechanisms: one involves a single, trusted dealer (see Appendix D of [FROST RFC draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/)), and the other requires performing a distributed key generation protocol (see [BIP FROST DKG draft](https://github.com/BlockstreamResearch/bip-frost-dkg)).

For a key generation mechanism to be compatible with FROST signing, the participant information it generates MUST successfully pass both the *ValidateThreshPubkey* and *ValidatePubshares* functions (see [Key Generation Compatibility](./README.md#key-generation-compatibility)).

> [!IMPORTANT]
> It should be noted that while passing these functions ensures functional compatibility, it does not guarantee the security of the key generation mechanism.

### General Signing Flow

FROST signing is designed to be executed by a predetermined `u` number of signing participants. This value is a positive non-zero integer that MUST be at least `t` and MUST NOT exceed `n`. Therefore, the selection of signing participants from the participant group must be performed outside the signing protocol, prior to its initiation.

Whenever the signing participants want to sign a message, the basic order of operations to create a threshold-signature is as follows:

**First broadcast round:**
The signers start the signing session by running *NonceGen* to compute *secnonce* and *pubnonce*.[^nonce-serialization-detail]
Then, the signers broadcast their *pubnonce* to each other and run *NonceAgg* to compute an aggregate nonce.

[^nonce-serialization-detail]: We treat the _secnonce_ and _pubnonce_ as grammatically singular even though they include serializations of two scalars and two elliptic curve points, respectively. This treatment may be confusing for readers familiar with the MuSig2 paper. However, serialization is a technical detail that is irrelevant for users of MuSig2 interfaces.

**Second broadcast round:**
At this point, every signer has the required data to sign, which, in the algorithms specified below, is stored in a data structure called [Session Context](./README.md#session-context).
Every signer computes a partial signature by running *Sign* with the participant identifier, the secret share, the *secnonce* and the session context.
Then, the signers broadcast their partial signatures to each other and run *PartialSigAgg* to obtain the final signature.
If all signers behaved honestly, the result passes [BIP340][bip340] verification.

Both broadcast rounds can be optimized by using a coordinator who collects all signers' nonces or partial signatures, aggregates them using *NonceAgg* or *PartialSigAgg*, respectively, and broadcasts the aggregate result back to the signers. A malicious coordinator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme, i.e., even a malicious coordinator colluding with all but one signer cannot forge a signature.

> [!IMPORTANT]
> The *Sign* algorithm must **not** be executed twice with the same *secnonce*.
> Otherwise, it is possible to extract the secret signing key from the two partial signatures output by the two executions of *Sign*.
> To avoid accidental reuse of *secnonce*, an implementation may securely erase the *secnonce* argument by overwriting it with 64 zero bytes after it has been read by *Sign*.
> A *secnonce* consisting of only zero bytes is invalid for *Sign* and will cause it to fail.

To simplify the specification of the algorithms, some intermediary values are unnecessarily recomputed from scratch, e.g., when executing *GetSessionValues* multiple times.
Actual implementations can cache these values.
As a result, the [Session Context](./README.md#session-context) may look very different in implementations or may not exist at all.
However, computation of *GetSessionValues* and storage of the result must be protected against modification from an untrusted third party.
This party would have complete control over the aggregate public key and message to be signed.

### Nonce Generation

> [!IMPORTANT]
> *NonceGen* must have access to a high-quality random generator to draw an unbiased, uniformly random value *rand'*.
> In contrast to BIP340 signing, the values *k<sub>1</sub>* and *k<sub>2</sub>* **must not be derived deterministically** from the session parameters because deriving nonces deterministically allows for a [complete key-recovery attack in multi-party discrete logarithm-based signatures](https://medium.com/blockstream/musig-dn-schnorr-multisignatures-with-verifiably-deterministic-nonces-27424b5df9d6#e3b6).

The optional arguments to *NonceGen* enable a defense-in-depth mechanism that may prevent secret share exposure if *rand'* is accidentally not drawn uniformly at random.
If the value *rand'* was identical in two *NonceGen* invocations, but any other argument was different, the *secnonce* would still be guaranteed to be different as well (with overwhelming probability), and thus accidentally using the same *secnonce* for *Sign* in both sessions would be avoided.
Therefore, it is recommended to provide the optional arguments *secshare*, *pubshare*, *thresh_pk*, and *m* if these session parameters are already determined during nonce generation.
The auxiliary input *extra_in* can contain additional contextual data that has a chance of changing between *NonceGen* runs,
e.g., a supposedly unique session id (taken from the application), a session counter wide enough not to repeat in practice, any nonces by other signers (if already known), or the serialization of a data structure containing multiple of the above.
However, the protection provided by the optional arguments should only be viewed as a last resort.
In most conceivable scenarios, the assumption that the arguments are different between two executions of *NonceGen* is relatively strong, particularly when facing an active adversary.

In some applications, it is beneficial to generate and send a *pubnonce* before the other signers, their *pubshare*, or the message to sign is known.
In this case, only the available arguments are provided to the *NonceGen* algorithm.
After this preprocessing phase, the *Sign* algorithm can be run immediately when the message and set of signers is determined.
This way, the final signature is created quicker and with fewer round trips.
However, applications that use this method presumably store the nonces for a longer time and must therefore be even more careful not to reuse them.
Moreover, this method is not compatible with the defense-in-depth mechanism described in the previous paragraph.

Instead of every signer broadcasting their *pubnonce* to every other signer, the signers can send their *pubnonce* to a single coordinator node that runs *NonceAgg* and sends the *aggnonce* back to the signers.
This technique reduces the overall communication.
A malicious coordinator can force the signing session to fail to produce a valid Schnorr signature but cannot negatively affect the unforgeability of the scheme.

In general, FROST signers are stateful in the sense that they first generate *secnonce* and then need to store it until they receive the other signers' *pubnonces* or the *aggnonce*.
However, it is possible for one of the signers to be stateless.
This signer waits until it receives the *pubnonce* of all the other signers and until session parameters such as a message to sign, participant identifiers, participant public shares, and tweaks are determined.
Then, the signer can run *NonceGen*, *NonceAgg* and *Sign* in sequence and send out its *pubnonce* along with its partial signature.
Stateless signers may want to consider signing deterministically (see [Modifications to Nonce Generation](./README.md#modifications-to-nonce-generation)) to remove the reliance on the random number generator in the *NonceGen* algorithm.

### Identifying Disruptive Signers

The signing protocol makes it possible to identify malicious signers who send invalid contributions to a signing session in order to make the signing session abort and prevent the honest signers from obtaining a valid signature.
This property is called "identifiable aborts" and ensures that honest parties can assign blame to malicious signers who cause an abort in the signing protocol.

Aborts are identifiable for an honest party if the following conditions hold in a signing session:
- The contributions received from all signers have not been tampered with (e.g., because they were sent over authenticated connections).
- Nonce aggregation is performed honestly (e.g., because the honest signer performs nonce aggregation on its own or because the coordinator is trusted).
- The partial signatures received from all signers are verified using the algorithm *PartialSigVerify*.

If these conditions hold and an honest party (signer or coordinator) runs an algorithm that fails due to invalid protocol contributions from malicious signers, then the algorithm run by the honest party will output the participant identifier of exactly one malicious signer.
Additionally, if the honest parties agree on the contributions sent by all signers in the signing session, all the honest parties who run the aborting algorithm will identify the same malicious signer.

#### Further Remarks

Some of the algorithms specified below may also assign blame to a malicious coordinator.
While this is possible for some particular misbehavior of the coordinator, it is not guaranteed that a malicious coordinator can be identified.
More specifically, a malicious coordinator (whose existence violates the second condition above) can always make signing abort and wrongly hold honest signers accountable for the abort (e.g., by claiming to have received an invalid contribution from a particular honest signer).

The only purpose of the algorithm *PartialSigVerify* is to ensure identifiable aborts, and it is not necessary to use it when identifiable aborts are not desired.
In particular, partial signatures are *not* signatures.
An adversary can forge a partial signature, i.e., create a partial signature without knowing the secret share for that particular participant public share.[^partialsig-forgery]
However, if *PartialSigVerify* succeeds for all partial signatures then *PartialSigAgg* will return a valid Schnorr signature.


[^partialsig-forgery]: Assume a malicious participant intends to forge a partial signature for the participant with public share *P*. It participates in the signing session pretending to be two distinct signers: one with the public share *P* and the other with its own public share. The adversary then sets the nonce for the second signer in such a way that allows it to generate a partial signature for *P*. As a side effect, it cannot generate a valid partial signature for its own public share. An explanation of the steps required to create a partial signature forgery can be found in [this document](docs/partialsig_forgery.md).

### Tweaking the Threshold Public Key

The threshold public key can be *tweaked*, which modifies the key as defined in the [Tweaking Definition](./README.md#tweaking-definition) subsection.
In order to apply a tweak, the Tweak Context output by *TweakCtxInit* is provided to the *ApplyTweak* algorithm with the *is_xonly_t* argument set to false for plain tweaking and true for X-only tweaking.
The resulting Tweak Context can be used to apply another tweak with *ApplyTweak* or obtain the threshold public key with *GetXonlyPubkey* or *GetPlainPubkey*.

The purpose of supporting tweaking is to ensure compatibility with existing uses of tweaking, i.e., that the result of signing is a valid signature for the tweaked public key.
The FROST signing algorithms take arbitrary tweaks as input but accepting arbitrary tweaks may negatively affect the security of the scheme.[^arbitrary-tweaks]
Instead, signers should obtain the tweaks according to other specifications.
This typically involves deriving the tweaks from a hash of the aggregate public key and some other information.
Depending on the specific scheme that is used for tweaking, either the plain or the X-only aggregate public key is required.
For example, to do [BIP32][bip32] derivation, you call *GetPlainPubkey* to be able to compute the tweak, whereas [BIP341][bip341] TapTweaks require X-only public keys that are obtained with *GetXonlyPubkey*.

[^arbitrary-tweaks]: It is an open question whether allowing arbitrary tweaks from an adversary affects the unforgeability of FROST.

The tweak mode provided to *ApplyTweak* depends on the application:
Plain tweaking can be used to derive child public keys from an aggregate public key using [BIP32][bip32].
On the other hand, X-only tweaking is required for Taproot tweaking per [BIP341][bip341].
A Taproot-tweaked public key commits to a *script path*, allowing users to create transaction outputs that are spendable either with a FROST threshold-signature or by providing inputs that satisfy the script path.
Script path spends require a control block that contains a parity bit for the tweaked X-only public key.
The bit can be obtained with *GetPlainPubkey(tweak_ctx)[0] & 1*.

## Algorithms

The following specification of the algorithms has been written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation and space. In particular, some values are recomputed but can be cached in actual implementations (see [General Signing Flow](./README.md#general-signing-flow)).

### Notation
<!-- TODO: remove this section (add a small note) as we're using secp256k1lab python library for scalar and group operations. Also, remove these wrapper functions from python code. -->
<!-- Should we just use the secp256k1lab's variable, or function calls here? For defining the curver order? -->
The following conventions are used, with constants as defined for [secp256k1](https://www.secg.org/sec2-v2.pdf). We note that adapting this proposal to other elliptic curves is not straightforward and can result in an insecure scheme.

- Lowercase variables represent integers or byte arrays.
  - The constant *p* refers to the field size, *0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F*.
  - The constant *curve_order* refers to the curve order, *0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141*.
- Uppercase variables refer to points on the curve with equation *y<sup>2</sup> = x<sup>3</sup> + 7* over the integers modulo *p*.
  - *is_infinite(P)* returns whether *P* is the point at infinity.
  - *x(P)* and *y(P)* are integers in the range *0..p-1* and refer to the X and Y coordinates of a point *P* (assuming it is not infinity).
  - The constant *G* refers to the base point, for which *x(G) = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798* and *y(G) = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8*.
  - Addition of points refers to the usual [elliptic curve group operation](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law).
  - [Multiplication (⋅) of an integer and a point](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication) refers to the repeated application of the group operation.
- Functions and operations:
  - *||* refers to byte array concatenation.
  - The function *x[i:j]*, where *x* is a byte array and *i, j ≥ 0*, returns a *(j - i)*-byte array with a copy of the *i*th byte (inclusive) to the *j*th byte (exclusive) of *x*.
  - The function *bytes(n, x)*, where *x* is an integer, returns the n-byte encoding of *x*, most significant byte first.
  - The constant *empty_bytestring* refers to the empty byte array. It holds that *len(empty_bytestring) = 0*.
  - The function *xbytes(P)*, where *P* is a point for which *not is_infinite(P)*, returns *bytes(32, x(P))*.
  - The function *len(x)* where *x* is a byte array returns the length of the array.
  - The function *has_even_y(P)*, where *P* is a point for which *not is_infinite(P)*, returns *y(P) mod 2 == 0*.
  - The function *with_even_y(P)*, where *P* is a point, returns *P* if *is_infinite(P)* or *has_even_y(P)*. Otherwise, *with_even_y(P)* returns *-P*.
  - The function *cbytes(P)*, where *P* is a point for which *not is_infinite(P)*, returns *a || xbytes(P)* where *a* is a byte that is *2* if *has_even_y(P)* and *3* otherwise.
  - The function *cbytes_ext(P)*, where *P* is a point, returns *bytes(33, 0)* if *is_infinite(P)*. Otherwise, it returns *cbytes(P)*.
  - The function *int(x)*, where *x* is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is *x*.
  - The function *lift_x(x)*, where *x* is an integer in range *0..2<sup>256</sup>-1*, returns the point *P* for which *x(P) = x*[^liftx-soln] and *has_even_y(P)*, or fails if *x* is greater than *p-1* or no such point exists. The function *lift_x(x)* is equivalent to the following pseudocode:
		- Fail if *x > p-1*.
		- Let *c = x<sup>3</sup> + 7 mod p*.
		- Let *y' = c<sup>(p+1)/4</sup> mod p*.
		- Fail if *c ≠ y'<sup>2</sup> mod p*.
		 - Let *y = y'* if *y' mod 2 = 0*, otherwise let *y = p - y'* .
		- Return the unique point *P* such that *x(P) = x* and *y(P) = y*.
  - The function *cpoint(x)*, where *x* is a 33-byte array (compressed serialization), sets *P = lift_x(int(x[1:33]))* and fails if that fails. If *x[0] = 2* it returns *P* and if *x[0] = 3* it returns *-P*. Otherwise, it fails.
  - The function *cpoint_ext(x)*, where *x* is a 33-byte array (compressed serialization), returns the point at infinity if *x = bytes(33, 0)*. Otherwise, it returns *cpoint(x)* and fails if that fails.
  - The function *hash<sub>tag</sub>(x)* where *tag* is a UTF-8 encoded tag name and *x* is a byte array returns the 32-byte hash *SHA256(SHA256(tag) || SHA256(tag) || x)*.
  - The function *count(lst, x)*, where *lst* is a list of integers containing *x*, returns the number of times *x* appears in *lst*.
  - The function *has_unique_elements(lst)*, where *lst* is a list of integers, returns True if *count(lst, x)* returns 1 for all *x* in *lst*. Otherwise returns False. The function *has_unique_elements(lst)* is equivalent to the following pseudocode:
    - For *x* in *lst*:
          - if *count(lst, x)* > 1:
      - Return False
    - Return True
  - The function *sorted(lst)*, where *lst* is a list of integers, returns a new list of integers in ascending order.
- Other:
  - Tuples are written by listing the elements within parentheses and separated by commas. For example, *(2, 3, 1)* is a tuple.


[^liftx-soln]: Given a candidate X coordinate *x* in the range *0..p-1*, there exist either exactly two or exactly zero valid Y coordinates. If no valid Y coordinate exists, then *x* is not a valid X coordinate either, i.e., no point *P* exists for which *x(P) = x*. The valid Y coordinates for a given candidate *x* are the square roots of *c = x<sup>3</sup> + 7 mod p* and they can be computed as *y = ±c<sup>(p+1)/4</sup> mod p* (see [Quadratic residue](https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus)) if they exist, which can be checked by squaring and comparing with *c*.

### Key Generation Compatibility

Internal Algorithm *PlainPubkeyGen(sk):*[^pubkey-gen-ecdsa]
- Input:
  - The secret key *sk*: a 32-byte array, freshly generated uniformly at random
- Let *d' = int(sk)*.
- Fail if *d' = 0* or *d' ≥ n*.
- Return *cbytes(d'⋅G)*.
<!-- REVIEW maybe write scripts to automate these italics (math symbols)? -->
Algorithm *ValidatePubshares(secshare<sub>1..u</sub>, pubshare<sub>1..u</sub>)*
- Inputs:
  - The number *u* of participants involved in keygen: an integer equal to `n`
  - The participant secret shares *secshare<sub>1..u</sub>*: *u* 32-byte arrays
  - The corresponding public shares *pubshare<sub>1..u</sub>*: *u* 33-byte arrays
- For *i = 1 .. u*:
  - Fail if *PlainPubkeyGen(secshare<sub>i</sub>)* ≠ *pubshare<sub>i</sub>*
- Return success iff no failure occurred before reaching this point.

[^pubkey-gen-ecdsa]: The _PlainPubkeyGen_ algorithm matches the key generation procedure traditionally used for ECDSA in Bitcoin

Algorithm *ValidateThreshPubkey(t, thresh_pk, id<sub>1..n</sub>, pubshare<sub>1..n</sub>)*:
- Inputs:
  - The total number *n* of participants involved in key generation
  - The threshold number *t* of participants required to issue a signature
  - The threshold public key *thresh_pk*: a 33-byte array
  - The participant identifiers *id<sub>1..n</sub>*: *n* integers in the range *[0..n-1]*
  - The participant public shares *pubshares<sub>1..n</sub>*: *n* 33-byte arrays
- Fail if *t* > *n*
- For *k* = *t..n*:
  - For each combination of *k* elements from *id<sub>1..n</sub>*:[^itertools-combinations]
    - Let *signer_id<sub>1..k</sub>* be the current combination of participant identifiers
    - Let *signer_pubshare<sub>1..k</sub>* be their corresponding participant pubshares[^calc-signer-pubshares]
    - Let *signer_signers = (n, t, k, signer_id<sub>1..k</sub>, signer_pubshare<sub>1..k</sub>)*
    - *expected_pk* = *DeriveThreshPubkey(signer_signers)*
    - Fail if *thresh_pk* ≠ *expected_pk*
- Return success iff no failure occurred before reaching this point.

[^itertools-combinations]: This line represents a loop over every possible combination of `t` elements sourced from the `int_ids` array. This operation is equivalent to invoking the [`itertools.combinations(int_ids, t)`](https://docs.python.org/3/library/itertools.html#itertools.combinations) function call in Python.

[^calc-signer-pubshares]: This *signer_pubshare<sub>1..t</sub>* list can be computed from the input *pubshare<sub>1..u</sub>* list.<br>
Method 1 - use `itertools.combinations(zip(int_ids, pubshares), t)`<br>
Method 2 - For *i = 1..t* :  signer_pubshare<sub>i</sub> = pubshare<sub>signer_id<sub>i</sub></sub>

### Tweaking the Threshold Public Key

#### Signers Context

The Signers Context is a data structure consisting of the following elements:
- The total number *n* of participants involved in key generation: an integer with *2 ≤ n < 2<sup>32</sup>*
- The threshold number *t* of participants required to issue a signature: a positive integer with *t ≤ n*
- The number *u* of participants available in the signing session with *t ≤ u ≤ n*
- The participant identifiers *id<sub>1..u</sub>*: *u* integers, each with 0 ≤ *id<sub>i</sub>* < *n*
- The individual public shares *pubshare<sub>1..u</sub>*: *u* 33-byte arrays

We write "Let *(n, t, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers*" to assign names to the elements of Signers Context.

#### Tweak Context

The Tweak Context is a data structure consisting of the following elements:
- The point *Q* representing the potentially tweaked threshold public key: an elliptic curve point
- The accumulated tweak *tacc*: an integer with *0 ≤ tacc < n*
- The value *gacc*: 1 or -1 mod n

We write "Let *(Q, gacc, tacc) = tweak_ctx*" to assign names to the elements of a Tweak Context.

Algorithm *TweakCtxInit(signers):*
- Input:
  - The *signers*: a [Signers Context](#signers-context) data structure
- Let *thresh_pk = DeriveThreshPubkey(signers)*; fail if that fails
- Let *Q = cpoint(thresh_pk)*
- Fail if *is_infinite(Q)*.
- Let *gacc = 1*
- Let *tacc = 0*
- Return *tweak_ctx = (Q, gacc, tacc)*.

Internal Algorithm *DeriveThreshPubkey(signers)*
- Let *(_, _, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers*
- *inf_point = bytes(33, 0)*
- *Q = cpoint_ext(inf_point)*
- For *i* = *1..u*:
  - *P* = *cpoint(pubshare<sub>i</sub>)*; fail if that fails
  - *lambda* = *DeriveInterpolatingValue(id<sub>1..u</sub>, id<sub>i</sub>)*
  - *Q* = *Q* + *lambda⋅P*
- Return *cbytes(Q)*

Internal Algorithm *DeriveInterpolatingValue(id<sub>1..u</sub>, my_id):*
- Fail if *my_id* not in *id<sub>1..u</sub>_
- Fail if not *has_unique_elements(id<sub>1..u</sub>)*
- Let *num = 1*
- Let *denom = 1*
- For *i = 1..u*:
  - If *id<sub>i</sub>* ≠ *my_id*:
	    - Let *num* = *num⋅(id<sub>i</sub>* + 1)
	    - Let *denom* = *denom⋅(id<sub>i</sub> - my_id)*
- *lambda* = *num⋅denom<sup>-1</sup> mod n*
- Return *lambda*

Algorithm *GetXonlyPubkey(tweak_ctx)*:
- Let *(Q, _, _) = tweak_ctx*
- Return *xbytes(Q)*

Algorithm *GetPlainPubkey(tweak_ctx)*:
- Let *(Q, _, _) = tweak_ctx*
- Return *cbytes(Q)*

#### Applying Tweaks

Algorithm *ApplyTweak(tweak_ctx, tweak, is_xonly_t)*:
- Inputs:
  - The *tweak_ctx*: a [Tweak Context](./README.md#tweak-context) data structure
  - The *tweak*: a 32-byte array
  - The tweak mode *is_xonly_t*: a boolean
- Let *(Q, gacc, tacc) = tweak_ctx*
- If *is_xonly_t* and *not has_even_y(Q)*:
  - Let *g = -1 mod n*
- Else:
  - Let *g = 1*
- Let *t = int(tweak)*; fail if *t ≥ n*
- Let *Q' = g⋅Q + t⋅G*
  - Fail if *is_infinite(Q')*
- Let *gacc' = g⋅gacc mod n*
- Let *tacc' = t + g⋅tacc mod n*
- Return *tweak_ctx' = (Q', gacc', tacc')*

### Nonce Generation

Algorithm *NonceGen(secshare, pubshare, thresh_pk, m, extra_in)*:
- Inputs:
  - The participant’s secret share *secshare*: a 32-byte array (optional argument)
  - The corresponding public share *pubshare*: a 33-byte array (optional argument)
  - The x-only threshold public key *thresh_pk*: a 32-byte array (optional argument)
  - The message *m*: a byte array (optional argument)[^max-msg-len]
  - The auxiliary input *extra_in*: a byte array with *0 ≤ len(extra_in) ≤ 2<sup>32</sup>-1* (optional argument)
- Let *rand'* be a 32-byte array freshly drawn uniformly at random
- If the optional argument *secshare* is present:
  - Let *rand* be the byte-wise xor of *secshare* and *hash<sub>FROST/aux</sub>(rand')*[^sk-xor-rand]
- Else:
  - Let *rand = rand'*
- If the optional argument *pubshare* is not present:
  - Let *pubshare* = *empty_bytestring*
- If the optional argument *thresh_pk* is not present:
  - Let *thresh_pk* = *empty_bytestring*
- If the optional argument *m* is not present:
  - Let *m_prefixed = bytes(1, 0)*
- Else:
  - Let *m_prefixed = bytes(1, 1) || bytes(8, len(m)) || m*
- If the optional argument *extra_in* is not present:
  - Let *extra_in = empty_bytestring*
- Let *k<sub>i</sub> = int(hash<sub>FROST/nonce</sub>(rand || bytes(1, len(pubshare)) || pubshare || bytes(1, len(thresh_pk)) || thresh_pk || m_prefixed || bytes(4, len(extra_in)) || extra_in || bytes(1, i - 1))) mod n* for *i = 1,2*
- Fail if *k<sub>1</sub> = 0* or *k<sub>2</sub> = 0*
- Let *R<sub>⁎,1</sub> = k<sub>1</sub>⋅G, R<sub>⁎,2</sub> = k<sub>2</sub>⋅G*
- Let *pubnonce = cbytes(R<sub>,1</sub>) || cbytes(R<sub>⁎,2</sub>)*
- Let *secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)*[^secnonce-ser]
- Return *(secnonce, pubnonce)*


[^sk-xor-rand]: The random data is hashed (with a unique tag) as a precaution against situations where the randomness may be correlated with the secret signing key itself. It is xored with the secret key (rather than combined with it in a hash) to reduce the number of operations exposed to the actual secret key.

[^secnonce-ser]: The algorithms as specified here assume that the *secnonce* is stored as a 64-byte array using the serialization *secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)*. The same format is used in the reference implementation and in the test vectors. However, since the *secnonce* is (obviously) not meant to be sent over the wire, compatibility between implementations is not a concern, and this method of storing the *secnonce* is merely a suggestion.    The *secnonce* is effectively a local data structure of the signer which comprises the value triple *(k<sub>1</sub>, k<sub>2</sub>)*, and implementations may choose any suitable method to carry it from *NonceGen* (first communication round) to *Sign* (second communication round). In particular, implementations may choose to hide the *secnonce* in internal state without exposing it in an API explicitly, e.g., in an effort to prevent callers from reusing a *secnonce* accidentally.

[^max-msg-len]: In theory, the allowed message size is restricted because SHA256 accepts byte strings only up to size of 2^61-1 bytes (and because of the 8-byte length encoding).

### Nonce Aggregation

Algorithm *NonceAgg(pubnonce<sub>1..u</sub>, id<sub>1..u</sub>)*:
- Inputs:
  - The number of signers *u*: an integer with *t ≤ u ≤ n*
  - The public nonces *pubnonce<sub>1..u</sub>*: *u* 66-byte arrays
  - The participant identifiers *id<sub>1..u</sub>*: *u* integers, each with 0 ≤ *id<sub>i</sub>* < *n*
- For *j = 1 .. 2*:
  - For *i = 1 .. u*:
    - Let *R<sub>i,j</sub> = cpoint(pubnonce<sub>i</sub>[(j-1)*33:j*33])*; fail if that fails and blame signer *id<sub>i</sub>* for invalid *pubnonce*.
  - Let *R<sub>j</sub> = R<sub>1,j</sub> + R<sub>2,j</sub> + ... + R<sub>u,j</sub>*
- Return *aggnonce = cbytes_ext(R<sub>1</sub>) || cbytes_ext(R<sub>2</sub>)*

### Session Context

The Session Context is a data structure consisting of the following elements:
- The *signers*: a [Signers Context](#signers-context) data structure
- The aggregate public nonce of signers *aggnonce*: a 66-byte array
- The number *v* of tweaks with *0 ≤ v < 2^32*
- The tweaks *tweak<sub>1..v</sub>*: *v* 32-byte arrays
- The tweak modes *is_xonly_t<sub>1..v</sub>* : *v* booleans
- The message *m*: a byte array[^max-msg-len]

We write "Let *(signers, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx*" to assign names to the elements of a Session Context.

For brevity, when we need to access the individual elements of *signers* within an algorithm, we may write:
"Let *(n, t, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers*"

Algorithm *GetSessionValues(session_ctx)*:
- Let *(signers, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m) = session_ctx*
- Let *(_, _, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers*
- Let *tweak_ctx<sub>0</sub> = TweakCtxInit(signers)*; fail if that fails
- For *i = 1 .. v*:
  - Let *tweak_ctx<sub>i</sub> = ApplyTweak(tweak_ctx<sub>i-1</sub>, tweak<sub>i</sub>, is_xonly_t<sub>i</sub>)*; fail if that fails
- Let *(Q, gacc, tacc) = tweak_ctx<sub>v</sub>*
- Let *ser_ids* = *SerializeIds(id<sub>1..u</sub>)*
- Let *b* = *int(hash<sub>FROST/noncecoef</sub>(ser_ids || aggnonce || xbytes(Q) || m)) mod n*
- Let *R<sub>1</sub> = cpoint_ext(aggnonce[0:33]), R<sub>2</sub> = cpoint_ext(aggnonce[33:66])*; fail if that fails and blame nonce coordinator for invalid *aggnonce*.
- Let *R' = R<sub>1</sub> + b⋅R<sub>2</sub>*
- If *is_infinite(R'):*
  - Let final nonce *R = G* ([see Dealing with Infinity in Nonce Aggregation](./README.md#dealing-with-infinity-in-nonce-aggregation))
- Else:
  - Let final nonce *R = R'*
- Let *e = int(hash<sub>BIP0340/challenge</sub>((xbytes(R) || xbytes(Q) || m))) mod n*
- Return (Q, gacc, tacc, b, R, e)

<!-- REVIEW should we check for duplicates and id value range here? -->
Internal Algorithm *SerializeIds(id<sub>1..u</sub>)*:
- *res = empty_bytestring*
- For *id* in *sorted(id<sub>1..u</sub>)*:
  - *res = res || bytes(4, id)*
- Return *res*

Algorithm *GetSessionInterpolatingValue(session_ctx, my_id)*:
- Let (signers, _, _, _, _, _) = session_ctx
- Let (_, _, u, id<sub>1..u</sub>, _) = signers
- Return *DeriveInterpolatingValue(id<sub>1..u</sub>, my_id)*; fail if that fails

Algorithm *SessionHasSignerPubshare(session_ctx, signer_pubshare)*:
- Let *(signers, _, _, _, _, _) = session_ctx*
- Let *(_, _, u, _, pubshare<sub>1..u</sub>) = signers*
- If *signer_pubshare in pubshare<sub>1..u</sub>*
	- Return True
- Otherwise Return False

### Signing

Algorithm *Sign(secnonce, secshare, my_id, session_ctx)*:
- Inputs:
  - The secret nonce *secnonce* that has never been used as input to *Sign* before: a 64-byte array[^secnonce-ser]
  - The secret signing key *secshare*: a 32-byte array
  - The identifier of the signing participant *my_id*: an integer with *0 ≤ my_id < n*
  - The *session_ctx*: a [Session Context](./README.md#session-context) data structure
- Let *(Q, gacc, _, b, R, e) = GetSessionValues(session_ctx)*; fail if that fails
- Let *k<sub>1</sub>' = int(secnonce[0:32]), k<sub>2</sub>' = int(secnonce[32:64])*
- Fail if *k<sub>i</sub>' = 0* or *k<sub>i</sub>' ≥ n* for *i = 1..2*
- Let *k<sub>1</sub> = k<sub>1</sub>', k<sub>2</sub> = k<sub>2</sub>'* if *has_even_y(R)*, otherwise let *k<sub>1</sub> = n - k<sub>1</sub>', k<sub>2</sub> = n - k<sub>2</sub>'*
- Let *d' = int(secshare)*
- Fail if *d' = 0* or *d' ≥ n*
- Let *P = d'⋅G*
- Let *pubshare = cbytes(P)*
- Fail if *SessionHasSignerPubshare(session_ctx, pubshare) = False*
- Let *λ = GetSessionInterpolatingValue(session_ctx, my_id)*; fail if that fails
- Let *g = 1* if *has_even_y(Q)*, otherwise let *g = -1 mod n*
- Let *d = g⋅gacc⋅d' mod n* (See [*Negation of Secret Share When Signing*](./README.md#negation-of-the-secret-share-when-signing))
- Let *s = (k<sub>1</sub> + b⋅k<sub>2</sub> + e⋅λ⋅d) mod n*
- Let *psig = bytes(32, s)*
- Let *pubnonce = cbytes(k<sub>1</sub>'⋅G) || cbytes(k<sub>2</sub>'⋅G)*
- If *PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)* (see below) returns failure, fail[^why-verify-partialsig]
- Return partial signature *psig*




[^why-verify-partialsig]: Verifying the signature before leaving the signer prevents random or adversarially provoked computation errors. This prevents publishing invalid signatures which may leak information about the secret key. It is recommended but can be omitted if the computation cost is prohibitive.

### Partial Signature Verification

Algorithm *PartialSigVerify(psig, pubnonce<sub>1..u</sub>, signers, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m, i)*:
- Inputs:
  - The partial signature *psig*: a 32-byte array
  - The public nonces *pubnonce<sub>1..u</sub>*: *u* 66-byte arrays
  - The *signers*: a [Signers Context](#signers-context) data structure
  - The number *v* of tweaks with *0 ≤ v < 2^32*
  - The tweaks *tweak<sub>1..v</sub>*: *v* 32-byte arrays
  - The tweak modes *is_xonly_t<sub>1..v</sub>* : *v* booleans
  - The message *m*: a byte array[^max-msg-len]
  - The index *i* of the signer in the list of public nonces where *0 < i ≤ u*
- Let *(_, _, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers*
- Let *aggnonce = NonceAgg(pubnonce<sub>1..u</sub>, id<sub>1..u</sub>)*; fail if that fails
- Let *session_ctx = (signers, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m)*
- Run *PartialSigVerifyInternal(psig, id<sub>i</sub>, pubnonce<sub>i</sub>, pubshare<sub>i</sub>, session_ctx)*
- Return success iff no failure occurred before reaching this point.

Internal Algorithm *PartialSigVerifyInternal(psig, my_id, pubnonce, pubshare, session_ctx)*:
- Let *(Q, gacc, _, b, R, e) = GetSessionValues(session_ctx)*; fail if that fails
- Let *s = int(psig)*; fail if *s ≥ n*
- Fail if *SessionHasSignerPubshare(session_ctx, pubshare) = False_
- Let *R<sub>⁎,1</sub> = cpoint(pubnonce[0:33]), R<sub>⁎,2</sub> = cpoint(pubnonce[33:66])*
- Let *Re<sub>⁎</sub>' = R<sub>⁎,1</sub> + b⋅R<sub>⁎,2</sub>*
- Let effective nonce *Re<sub>⁎</sub> = Re<sub>⁎</sub>'* if *has_even_y(R)*, otherwise let *Re<sub>⁎</sub> = -Re<sub>⁎</sub>'*
- Let *P = cpoint(pubshare)*; fail if that fails
- Let *λ = GetSessionInterpolatingValue(session_ctx, my_id)*[^lambda-cant-fail]
- Let *g = 1* if *has_even_y(Q)*, otherwise let *g = -1 mod n*
- Let *g' = g⋅gacc mod n* (See [*Negation of Pubshare When Partially Verifying*](./README.md#negation-of-the-pubshare-when-partially-verifying))
- Fail if *s⋅G ≠ Re<sub>⁎</sub> + e⋅λ⋅g'⋅P*
- Return success iff no failure occurred before reaching this point.


[^lambda-cant-fail]: *GetSessionInterpolatingValue(session_ctx, my_id)* cannot fail when called from *PartialSigVerifyInternal*.

### Partial Signature Aggregation

Algorithm *PartialSigAgg(psig<sub>1..u</sub>, id<sub>1..u</sub>, session_ctx)*:
- Inputs:
  - The number *u* of signatures with *t ≤ u ≤ n*
  - The partial signatures *psig<sub>1..u</sub>*: *u* 32-byte arrays
  - The participant identifiers *id<sub>1..u</sub>*: *u* integers, each with 0 ≤ *id<sub>i</sub>* < *n*
  - The *session_ctx*: a [Session Context](./README.md#session-context) data structure
- Let *(Q, _, tacc, _, _, R, e) = GetSessionValues(session_ctx)*; fail if that fails
- For *i = 1 .. u*:
  - Let *s<sub>i</sub> = int(psig<sub>i</sub>)*; fail if *s<sub>i</sub> ≥ n* and blame signer *id<sub>i</sub>* for invalid partial signature.
- Let *g = 1* if *has_even_y(Q)*, otherwise let *g = -1 mod n*
- Let *s = s<sub>1</sub> + ... + s<sub>u</sub> + e⋅g⋅tacc mod n*
- Return *sig =* xbytes(R) || bytes(32, s)

### Test Vectors & Reference Code

We provide a naive, highly inefficient, and non-constant time [pure Python 3 reference implementation of the threshold public key tweaking, nonce generation, partial signing, and partial signature verification algorithms](./reference/reference.py).

Standalone JSON test vectors are also available in the [same directory](./reference/vectors/), to facilitate porting the test vectors into other implementations.

> [!CAUTION]
> The reference implementation is for demonstration purposes only and not to be used in production environments.

## Remarks on Security and Correctness

### Modifications to Nonce Generation

Implementers must avoid modifying the *NonceGen* algorithm without being fully aware of the implications.
We provide two modifications to *NonceGen* that are secure when applied correctly and may be useful in special circumstances, summarized in the following table.

|  | needs secure randomness | needs secure counter | needs to keep state securely | needs aggregate nonce of all other signers (only possible for one signer) |
| --- | --- | --- | --- | --- |
| **NonceGen** | ✓ |  | ✓ |  |
| **CounterNonceGen** |  | ✓ | ✓ |  |
| **DeterministicSign** |  |  |  | ✓ |

First, on systems where obtaining uniformly random values is much harder than maintaining a global atomic counter, it can be beneficial to modify *NonceGen*.
The resulting algorithm *CounterNonceGen* does not draw *rand'* uniformly at random but instead sets *rand'* to the value of an atomic counter that is incremented whenever it is read.
With this modification, the secret share *secshare* of the signer generating the nonce is **not** an optional argument and must be provided to *NonceGen*.
The security of the resulting scheme then depends on the requirement that reading the counter must never yield the same counter value in two *NonceGen* invocations with the same *secshare*.

Second, if there is a unique signer who is supposed to send the *pubnonce* last, it is possible to modify nonce generation for this single signer to not require high-quality randomness.
Such a nonce generation algorithm *DeterministicSign* is specified below.
Note that the only optional argument is *rand*, which can be omitted if randomness is entirely unavailable.
*DeterministicSign* requires the argument *aggothernonce* which should be set to the output of *NonceAgg* run on the *pubnonce* value of **all** other signers (but can be provided by an untrusted party).
Hence, using *DeterministicSign* is only possible for the last signer to generate a nonce and makes the signer stateless, similar to the stateless signer described in the [Nonce Generation](./README.md#nonce-generation) section.
<!-- REVIEW just say n is < 2^32 during intro, than mentioning it everywhere -->

#### Deterministic and Stateless Signing for a Single Signer

Algorithm *DeterministicSign(secshare, my_id, aggothernonce, signers, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m, rand)*:
- Inputs:
  - The secret share *secshare*: a 32-byte array
  - The identifier of the signing participant *my_id*: an integer with 0 *≤ my_id < n*
  - The aggregate public nonce *aggothernonce* (see [above](./README.md#modifications-to-nonce-generation)): a 66-byte array
  - The *signers*: a [Signers Context](#signers-context) data structure
  - The number *v* of tweaks with *0 ≤ v < 2^32*
  - The tweaks *tweak<sub>1..v</sub>*: *v* 32-byte arrays
  - The tweak methods *is_xonly_t<sub>1..v</sub>*: *v* booleans
  - The message *m*: a byte array[^max-msg-len]
  - The auxiliary randomness *rand*: a 32-byte array (optional argument)
- If the optional argument *rand* is present:
  - Let *secshare'* be the byte-wise xor of *secshare* and *hash<sub>FROST/aux</sub>(rand)*
- Else:
  - Let *secshare' = secshare*
- Let (_, _, u, id<sub>1..u</sub>, pubshare<sub>1..u</sub>) = signers
- Let *tweak_ctx<sub>0</sub> = TweakCtxInit(signers)*; fail if that fails
- For *i = 1 .. v*:
  - Let *tweak_ctx<sub>i</sub> = ApplyTweak(tweak_ctx<sub>i-1</sub>, tweak<sub>i</sub>, is_xonly_t<sub>i</sub>)*; fail if that fails
- Let *tweaked_tpk = GetXonlyPubkey(tweak_ctx<sub>v</sub>)*
- Let *k<sub>i</sub> = int(hash<sub>FROST/deterministic/nonce</sub>(secshare' || aggothernonce || tweaked*tpk || bytes(8, len(m)) || m || bytes(1, i - 1))) mod n* for *i = 1,2_
- Fail if *k<sub>1</sub> = 0* or *k<sub>2</sub> = 0*
- Let *R<sub>⁎,1</sub> = k<sub>1</sub>⋅G, R<sub>⁎,2</sub> = k<sub>2</sub>⋅G*
- Let *pubnonce = cbytes(R<sub>⁎,2</sub>) || cbytes(R<sub>⁎,2</sub>)*
- Let *d = int(secshare)*
- Fail if *d = 0* or *d ≥ n*
- Let *signer_pubshare = cbytes(d⋅G)*
- Fail if *signer_pubshare* is not present in *pubshare<sub>1..u</sub>_
- Let *secnonce = bytes(32, k<sub>1</sub>) || bytes(32, k<sub>2</sub>)*
- Let *aggnonce = NonceAgg((pubnonce, aggothernonce), (my_id, COORDINATOR*ID))*; fail if that fails and blame coordinator for invalid *aggothernonce*.
- Let *session_ctx = (signers, aggnonce, v, tweak<sub>1..v</sub>, is_xonly_t<sub>1..v</sub>, m)*

### Tweaking Definition

Two modes of tweaking the threshold public key are supported. They correspond to the following algorithms:

Algorithm *ApplyPlainTweak(P, t)*:
- Inputs:
  - *P*: a point
  - The tweak *twk*: an integer with *0 ≤ twk < curve_order*
- Return *P + twk⋅G*

Algorithm *ApplyXonlyTweak(P, t)*:
- Return *with_even_y(P) + t⋅G*
- 
<!-- TODO: we could simply point to BIP327 for this proof. Unless we use agnostic tweaking -->
### Negation of the Secret Share when Signing

During the signing process, the *[Sign](./README.md#signing)* algorithm might have to negate the secret share in order to produce a partial signature for an X-only threshold public key. This public key is derived from *u* public shares and *u* participant identifiers (denoted by the signer set *U*) and then tweaked *v* times (X-only or plain).

The following elliptic curve points arise as intermediate steps when creating a signature:<br>
- *P<sub>i</sub>* as computed in any compatible key generation method is the point corresponding to the *i*-th signer's public share. Defining *d<sub>i</sub>'* to be the *i*-th signer's secret share as an integer, i.e., the *d’* value as computed in the *Sign* algorithm of the *i*-th signer, we have:<br>
&emsp;&ensp;*P<sub>i</sub> = d<sub>i</sub>'⋅G*<br>
- *Q<sub>0</sub>* is the threshold public key derived from the signer’s public shares. It is identical to the value *Q* computed in *DeriveThreshPubkey* and therefore defined as:<br>
&emsp;&ensp;_Q<sub>0</sub> = &lambda;<sub>1, U</sub>⋅P<sub>1</sub> + &lambda;<sub>2, U</sub>⋅P<sub>2</sub> + ... + &lambda;<sub>u, U</sub>⋅P<sub>u</sub>_<br>
- *Q<sub>i</sub>* is the tweaked threshold public key after the *i*-th execution of *ApplyTweak* for *1 ≤ i ≤ v*. It holds that<br>
&emsp;&ensp;*Q<sub>i</sub> = f(i-1) + t<sub>i</sub>⋅G* for *i = 1, ..., v* where<br>
&emsp;&ensp;&emsp;&ensp;*f(i-1) := with_even_y(Q<sub>i-1</sub>)* if *is_xonly_t<sub>i</sub>* and<br>
&emsp;&ensp;&emsp;&ensp;*f(i-1) := Q<sub>i-1</sub>* otherwise.<br>
- *with_even_y(Q*<sub>v</sub>*)* is the final result of the threshold public key derivation and tweaking operations. It corresponds to the output of *GetXonlyPubkey* applied on the final Tweak Context.

The signer's goal is to produce a partial signature corresponding to the final result of threshold pubkey derivation and tweaking, i.e., the X-only public key *with_even_y(Q<sub>v</sub>)*.

For *1 ≤ i ≤ v*, we denote the value *g* computed in the *i*-th execution of *ApplyTweak* by *g<sub>i-1</sub>*. Therefore, *g<sub>i-1</sub>* is *-1 mod n* if and only if *is_xonly_t<sub>i</sub>* is true and *Q<sub>i-1</sub>* has an odd Y coordinate. In other words, *g<sub>i-1</sub>* indicates whether *Q<sub>i-1</sub>* needed to be negated to apply an X-only tweak:<br>
&emsp;&ensp;*f(i-1) = g<sub>i-1</sub>⋅Q<sub>i-1</sub>* for *1 ≤ i ≤ v*.<br>
Furthermore, the *Sign* and *PartialSigVerify* algorithms set value *g* depending on whether Q<sub>v</sub> needed to be negated to produce the (X-only) final output. For consistency, this value *g* is referred to as *g<sub>v</sub>* in this section.<br>
&emsp;&ensp;*with_even_y(Q<sub>v</sub>) = g<sub>v</sub>⋅Q<sub>v</sub>*.

So, the (X-only) final public key is<br>
&emsp;&ensp;*with_even_y(Q<sub>v</sub>)*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅Q<sub>v</sub>*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅(f(v-1)* + *t<sub>v</sub>⋅G)*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅(g<sub>v-1</sub>⋅(f(v-2)* + *t<sub>v-1</sub>⋅G)* + *t<sub>v</sub>⋅G)*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅g<sub>v-1</sub>⋅f(v-2)* + *g<sub>v</sub>⋅(t<sub>v</sub>* + *g<sub>v-1</sub>⋅t<sub>v-1</sub>)⋅G*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅g<sub>v-1</sub>⋅f(v-2)* + *(sum<sub>i=v-1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>)⋅G*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅g<sub>v-1</sub>⋅...⋅g<sub>1</sub>⋅f(0)* + *(sum<sub>i=1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>)⋅G*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅...⋅g<sub>0</sub>⋅Q<sub>0</sub>* + *g<sub>v</sub>⋅tacc<sub>v</sub>⋅G*<br> 
&emsp;&ensp;where *tacc<sub>i</sub>* is computed by *TweakCtxInit* and *ApplyTweak* as follows:<br>
&emsp;&ensp;&emsp;&ensp;*tacc<sub>0</sub>* = *0*<br>
&emsp;&ensp;&emsp;&ensp;*tacc<sub>i</sub>* = *t<sub>i</sub>* + *g<sub>i-1</sub>⋅tacc<sub>i-1</sub> for i=1..v mod n*<br>
&emsp;&ensp;for which it holds that *g<sub>v</sub>⋅tacc<sub>v</sub>* = *sum<sub>i=1..v</sub> t<sub>i</sub>⋅prod<sub>j=i..v</sub> g<sub>j</sub>*.

*TweakCtxInit* and *ApplyTweak* compute<br>
&emsp;&ensp;*gacc<sub>0</sub>* = 1<br>
&emsp;&ensp;*gacc<sub>i</sub>* = *g<sub>i-1</sub>⋅gacc<sub>i-1</sub> for i=1..v mod n*<br>
So we can rewrite above equation for the final public key as<br>
&emsp;&ensp;*with_even_y(Q<sub>v</sub>)* = *g<sub>v</sub>⋅gacc<sub>v</sub>⋅Q<sub>0</sub>* + *g<sub>v</sub>⋅tacc<sub>v</sub>⋅G.*

Then we have<br>
&emsp;&ensp;*with_even_y(Q<sub>v</sub>)* - *g<sub>v</sub>⋅tacc<sub>v</sub>⋅G*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅gacc<sub>v</sub>⋅Q<sub>0</sub>*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅gacc<sub>v</sub>⋅(&lambda;<sub>1, U</sub>⋅P<sub>1</sub> + ... + &lambda;<sub>u, U</sub>⋅P<sub>u</sub>)*<br>
&emsp;&ensp;&emsp;&ensp;= *g<sub>v</sub>⋅gacc<sub>v</sub>⋅(&lambda;<sub>1, U</sub>⋅d<sub>1</sub>'⋅G + ... + &lambda;<sub>u, U</sub>⋅d<sub>u</sub>'⋅G)*<br>
&emsp;&ensp;&emsp;&ensp;= *sum<sub>i=1..u</sub>(g<sub>v</sub>⋅gacc<sub>v</sub>⋅&lambda;<sub>i, U</sub>⋅d<sub>i</sub>')\*G.*<br>

Intuitively, *gacc<sub>i</sub>* tracks accumulated sign flipping and *tacc<sub>i</sub>* tracks the accumulated tweak value after applying the first *i* individual tweaks. Additionally, *g<sub>v</sub>* indicates whether *Q<sub>v</sub>* needed to be negated to produce the final X-only result. Thus, signer *i* multiplies its secret share *d<sub>i</sub>'* with *g<sub>v</sub>⋅gacc<sub>v</sub>* in the [*Sign*](./README.md#signing) algorithm.

#### Negation of the Pubshare when Partially Verifying

As explained in [Negation Of The Secret Share When Signing](./README.md#negation-of-the-secret-share-when-signing) the signer uses a possibly negated secret share<br>
&emsp;&ensp;*d = g<sub>v</sub>⋅gacc<sub>v</sub>⋅d' mod n*<br>
when producing a partial signature to ensure that the aggregate signature will correspond to a threshold public key with even Y coordinate.

The [*PartialSigVerifyInternal*](./README.md#partial-signature-verification) algorithm is supposed to check<br>
&emsp;&ensp;*s⋅G = Re<sub>⁎</sub> + e⋅λ⋅d⋅G*.

The verifier doesn't have access to *d⋅G* but can construct it using the participant public share *pubshare* as follows:<br>
*d⋅G*<br>
&emsp;&ensp;*= g<sub>v</sub>⋅gacc<sub>v</sub>⋅d'⋅G*<br>
&emsp;&ensp;*= g<sub>v</sub>⋅gacc<sub>v</sub>⋅cpoint(pubshare)*<br>
Note that the threshold public key and list of tweaks are inputs to partial signature verification, so the verifier can also construct *g<sub>v</sub>* and *gacc<sub>v</sub>*.

### Dealing with Infinity in Nonce Aggregation

If the coordinator provides *aggnonce = bytes(33,0) || bytes(33,0)*, either the coordinator is dishonest or there is at least one dishonest signer (except with negligible probability).
If signing aborted in this case, it would be impossible to determine who is dishonest.
Therefore, signing continues so that the culprit is revealed when collecting and verifying partial signatures.

However, the final nonce *R* of a BIP340 Schnorr signature cannot be the point at infinity.
If we would nonetheless allow the final nonce to be the point at infinity, then the scheme would lose the following property:
if *PartialSigVerify* succeeds for all partial signatures, then *PartialSigAgg* will return a valid Schnorr signature.
Since this is a valuable feature, we modify FROST3 (which is defined in the section 2.3 of the [ROAST paper](https://eprint.iacr.org/2022/550.pdf)) to avoid producing an invalid Schnorr signature while still allowing detection of the dishonest signer: In *GetSessionValues*, if the final nonce *R* would be the point at infinity, set it to the generator instead (an arbitrary choice).

This modification to *GetSessionValues* does not affect the unforgeability of the scheme.
Given a successful adversary against the unforgeability game (EUF-CMA) for the modified scheme, a reduction can win the unforgeability game for the original scheme by simulating the modification towards the adversary:
When the adversary provides *aggnonce' = bytes(33, 0) || bytes(33, 0)*, the reduction sets *aggnonce = cbytes_ext(G) || bytes(33, 0)*.
For any other *aggnonce'*, the reduction sets *aggnonce = aggnonce'*.
(The case that the adversary provides an *aggnonce' ≠ bytes(33, 0) || bytes(33, 0)* but nevertheless *R'* in *GetSessionValues* is the point at infinity happens only with negligible probability.)

## Backwards Compatibility

This document proposes a standard for the FROST threshold signature scheme that is compatible with [BIP340][bip340]. FROST is *not* compatible with ECDSA signatures traditionally used in Bitcoin.

## Changelog

To help the reader understand updates to this document, we attach a version number that resembles "semantic versioning" (`MAJOR.MINOR.PATCH`).
The `MAJOR` version is incremented if changes to the BIP are introduced that are incompatible with prior versions.
An exception to this rule is `MAJOR` version zero (0.y.z) which is for development and does not need to be incremented if backwards-incompatible changes are introduced.
The `MINOR` version is incremented whenever the inputs or the output of an algorithm changes in a backward-compatible way or new backward-compatible functionality is added.
The `PATCH` version is incremented for other noteworthy changes (bug fixes, test vectors, important clarifications, etc.).

* *0.2.3* (2025-11-25): Sync terminologies with the ChillDKG BIP.
* *0.2.2* (2025-11-11): Remove key generation test vectors as key generation is out of scope for this specification.
* *0.2.1* (2025-11-10): Vendor secp256k1lab library to provide `Scalar` and `GE` primitives. Restructure reference implementation into a Python package layout.
* *0.2.0* (2025-04-11): Includes minor fixes and the following major changes:
  - Initialize `TweakCtxInit` using individual `pubshares` instead of the threshold public key.
  - Add Python script to automate generation of test vectors.
  - Represent participant identifiers as 4-byte integers in the range `0..n - 1` (inclusive).
* *0.1.0* (2024-07-31): Publication of draft BIP on the bitcoin-dev mailing list

## Acknowledgments

We thank Jonas Nick, Tim Ruffing, Jesse Posner, and Sebastian Falbesoner for their contributions to this document.

<!-- References -->
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[bip340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[bip341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[bip342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
[bip327]: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
[frost1]: https://eprint.iacr.org/2020/852
[frost2]: https://eprint.iacr.org/2021/1375
[stronger-security-frost]: https://eprint.iacr.org/2022/833
[olaf]: https://eprint.iacr.org/2023/899
[roast]: https://eprint.iacr.org/2022/550
[thresh-with-dkg]: https://link.springer.com/chapter/10.1007/3-540-36563-x_26

```html
<pre>
with_even_y(Q_v) - g_v·tacc_v·G
    = g_v·gacc_v·Q_0
    = g_v·gacc_v·(... P_i ...) 
    = ... *G 
</pre>

```math
\begin{aligned}
 \textit{with\_even\_y}(Q_v) - g_v\,tacc_v\,G 
   &= g_v\,gacc_v\,Q_0 \\
   &= g_v\,gacc_v\,(\lambda_{1,U}P_1 + \dots + \lambda_{u,U}P_u) \\
   &= g_v\,gacc_v\,(\lambda_{1,U}d'_1G + \dots + \lambda_{u,U}d'_uG) \\
   &= \sum_{i=1}^u g_v\,gacc_v\,\lambda_{i,U}d'_i\,G~.
\end{aligned}