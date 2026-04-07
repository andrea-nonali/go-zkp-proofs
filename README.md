# go-zkp-proofs

A Go library implementing production-quality **zero-knowledge equality proofs** for Pedersen commitments on the Ristretto255 elliptic curve.

The library lets a prover convince a verifier that two commitments encode the same secret value, without revealing that value or its blinding factors.

> **Looking for range proofs?** BulletProofs have been split into their own repository: [go-bulletproofs](https://github.com/andrea-nonali/go-bulletproofs).

---

## Table of Contents

- [What Are Zero-Knowledge Proofs?](#what-are-zero-knowledge-proofs)
- [Implemented Protocols](#implemented-protocols)
  - [Schnorr Equality Proof](#1-schnorr-equality-proof)
  - [Chaum-Pedersen Equality Proofs](#2-chaum-pedersen-equality-proofs)
- [Installation](#installation)
- [Usage](#usage)
  - [Schnorr](#schnorr)
  - [Chaum-Pedersen: Pedersen–Pedersen](#chaum-pedersen-pedersenpedersen-equality)
  - [Chaum-Pedersen: Pedersen–ElGamal](#chaum-pedersen-pedersenelgamal-equality)
- [Cryptographic Foundations](#cryptographic-foundations)
- [Security Considerations](#security-considerations)
- [Repository Layout](#repository-layout)
- [Further Reading](#further-reading)

---

## What Are Zero-Knowledge Proofs?

A zero-knowledge proof (ZKP) lets a **prover** convince a **verifier** that a statement is true without revealing *why* it is true, and without disclosing any secret witness.

### A real-world analogy: the bouncer at the door

Imagine you want to enter a club. The bouncer needs to know one thing: **are you over 18?** To prove it, you could hand over your ID. However, that also reveals your full name, home address, and exact date of birth. You shared far more than necessary.

A zero-knowledge proof is the equivalent of a bouncer who can be convinced you are over 18 **without learning anything else about you**. In practice this is exactly what modern age-verification systems are moving towards: a government-issued digital credential lets you prove a property ("age ≥ 18") without handing over the underlying document.

The same idea scales to much more sensitive statements:

- *"I know the password"* — without typing it.
- *"My bank balance is above €1,000"* — without showing the statement.
- *"This transaction doesn't overdraw my account"* — without revealing the balance or the amount.
- *"I voted, and my vote is valid"* — without revealing who I voted for.

### The three guarantees every ZKP must provide

- **Completeness**: an honest prover with a valid witness always convinces an honest verifier.
- **Soundness**: a cheating prover without a valid witness cannot convince the verifier, except with negligible probability.
- **Zero-knowledge**: the verifier learns nothing beyond the truth of the statement.

### Pedersen Commitments

All protocols in this library use **Pedersen commitments** as the commitment scheme:

```
C = m·G + r·H
```

where `G` and `H` are independent generators on Ristretto255, `m` is the secret message, and `r` is a random blinding factor. Pedersen commitments are:

- **Hiding** — `C` reveals nothing about `m` (perfect secrecy).
- **Binding** — a committed party cannot change `m` after the fact (computationally binding under DLOG).
- **Homomorphic** — `C(m₁,r₁) + C(m₂,r₂) = C(m₁+m₂, r₁+r₂)`.

---

## Implemented Protocols

### 1. Schnorr Equality Proof

**Package:** `schnorr`  
**Curve:** Ristretto255

#### What it proves

Given two Pedersen commitments:

```
C₁ = m·G + r₁·H
C₂ = m·G + r₂·H
```

the prover demonstrates they were built with the **same message `m`**, without revealing `m`, `r₁`, or `r₂`.

#### Protocol sketch

Let `C = C₁ − C₂ = (r₁−r₂)·H` (a commitment to 0 if and only if `m₁ = m₂`).

1. **Prover** picks random `ρ ∈ Zₚ`, computes `R = ρ·H`.
2. **Challenge** `c = SHA-256(C ‖ H ‖ R)`.
3. **Response** `z = (r₁−r₂)·c + ρ`.
4. **Verifier** recomputes `c' = SHA-256(C ‖ H ‖ z·H − c·C)` and checks `c == c'`.

Correctness: `z·H − c·C = ((r₁−r₂)·c + ρ)·H − c·(r₁−r₂)·H = ρ·H = R`. ✓

#### Real-world applications

| System | How Schnorr proofs are used |
|--------|-----------------------------|
| **Bitcoin Taproot** (BIP-340) | Schnorr signatures replace ECDSA; MuSig2 lets multiple parties aggregate keys and signatures into a single indistinguishable output, reducing fees and improving privacy. |
| **Ed25519 / EdDSA** | The signature scheme used by SSH keys, TLS 1.3, Ethereum validator keys, and Signal. A Schnorr-style construction on Curve25519. |
| **ZCash (Sapling)** | A modified Schnorr protocol is used inside the inner ZKP machinery to authorise shielded transactions without revealing sender, recipient, or amount. |
| **Decentralised identity (DID)** | Attribute-based credential systems let a user prove they hold a valid credential without revealing which one — the core primitive is a Schnorr proof of knowledge. |

---

### 2. Chaum-Pedersen Equality Proofs

**Package:** `chaumPedersen`  
**Curve:** Ristretto255

#### 2a. Pedersen–Pedersen Equality

Proves that two Pedersen commitments `C₁ = m·G + r₁·H` and `C₂ = m·G + r₂·H` share the same message `m`, using auxiliary commitments `C₃, C₄` and three response scalars.

**Verification equations:**

```
C₃ + c·C₁  ==  z₁·G + z₂·H
C₄ + c·C₂  ==  z₁·G + z₃·H
```

Both equations must hold simultaneously. Because both use `z₁` (bound to `m`), the two commitments are forced to encode the same value.

#### 2b. Pedersen–ElGamal Equality

Proves that a Pedersen commitment `C = m·G + r·H` and an ElGamal ciphertext `(E₁, E₂) = ElGamal.Encrypt(r, m·G, PK)` encode the **same plaintext `m`**.

**Verification equations:**

```
C₁ + c·C   ==  z₁·G + z₂·H       (Pedersen side)
E₁ + c·e₁  ==  z₂·G               (ElGamal first component)
E₂ + c·e₂  ==  z₁·G + z₂·PK      (ElGamal second component)
```

Useful in verifiable encryption and mix-nets where a sender must prove that a publicly encrypted value matches a committed one.

#### Real-world applications

| System | How Chaum-Pedersen proofs are used |
|--------|------------------------------------|
| **SwissPost e-voting** | Each ballot is ElGamal-encrypted; a Chaum-Pedersen proof attests that the encrypted vote matches the voter's committed choice, allowing public audit without decrypting any ballot. |
| **Estonia's i-voting** | The world's first country-wide internet voting system (since 2005). Re-encryption shuffle steps are verified using Chaum-Pedersen NIZKs so any observer can confirm ballots were shuffled correctly. |
---

## Installation

```bash
go get github.com/andrea-nonali/go-zkp-proofs
```

**Requirements:** Go 1.21+

**Dependencies:**

| Dependency | Used by | Purpose |
|------------|---------|---------|
| `github.com/bwesterb/go-ristretto v1.2.2` | `schnorr`, `chaumPedersen` | Ristretto255 curve arithmetic |
| `github.com/tuhoag/elliptic-curve-cryptography-go v0.0.4` | `schnorr`, `chaumPedersen` | Pedersen commitment & ElGamal helpers |

---

## Usage

### Schnorr

```go
import (
    "github.com/bwesterb/go-ristretto"
    "github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
    "github.com/andrea-nonali/go-zkp-proofs/schnorr"
)

var H ristretto.Point
H.Rand()
var m, r1, r2 ristretto.Scalar
m.Rand(); r1.Rand(); r2.Rand()

C1 := pedersen.CommitTo(&H, &m, &r1)
C2 := pedersen.CommitTo(&H, &m, &r2)

// Prove equality.
var proof schnorr.SchnorrProof
proof.Prove(&H, &m, &r1, &m, &r2)

// Verify (the verifier receives C = C1 − C2 and H).
var C ristretto.Point
C.Sub(C1, C2)
ok := proof.Verify(&C, &H) // true
```

---

### Chaum-Pedersen: Pedersen–Pedersen Equality

```go
import (
    "github.com/bwesterb/go-ristretto"
    "github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
    cp "github.com/andrea-nonali/go-zkp-proofs/chaum_pedersen"
)

var H ristretto.Point
H.Rand()
var m, r1, r2 ristretto.Scalar
m.Rand(); r1.Rand(); r2.Rand()

C1 := pedersen.CommitTo(&H, &m, &r1)
C2 := pedersen.CommitTo(&H, &m, &r2)

var proof cp.PedersenEquality
proof.Prove(&H, &m, &r1, &r2)

ok := proof.Verify(C1, C2) // true
```

---

### Chaum-Pedersen: Pedersen–ElGamal Equality

```go
import (
    "github.com/bwesterb/go-ristretto"
    "github.com/tuhoag/elliptic-curve-cryptography-go/elgamal"
    "github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
    cp "github.com/andrea-nonali/go-zkp-proofs/chaum_pedersen"
)

var H, PK ristretto.Point
H.Rand(); PK.Rand()
var m, r ristretto.Scalar
m.Rand(); r.Rand()

var mG ristretto.Point
mG.ScalarMultBase(&m)
e1, e2 := elgamal.Encrypt(&r, &mG, &PK)
C := pedersen.CommitTo(&H, &m, &r)

var proof cp.PedersenElgamalEquality
proof.Prove(&H, &PK, &m, &r)

ok := proof.Verify(C, e1, e2) // true
```

---

## Cryptographic Foundations

### Curve

Both packages use **Ristretto255** via [`go-ristretto`](https://github.com/bwesterb/go-ristretto). Ristretto255 is a prime-order group constructed from the Edwards25519 curve; it has cofactor 1 (no small-subgroup issues) and provides ~128-bit security.

### Fiat-Shamir Transform

All proofs are made non-interactive by replacing the verifier's random challenge with the SHA-256 hash of the transcript so far. This operates in the **random oracle model**; the security reduction holds under the assumption that SHA-256 behaves like a random oracle.

---

## Security Considerations

1. **Non-canonical hash input.** Challenges are derived by hashing the decimal string representations of curve points. This is not a canonical fixed-length encoding. For provable security replace with a fixed-length big-endian byte encoding and a domain-separation prefix per protocol.

2. **No domain separation.** There is no protocol identifier in the hash input. Do not use the same key material across both `schnorr` and `chaumPedersen` without adding distinct prefixes.

3. **Not audited.** This library is provided for educational and research purposes and has not undergone a professional security audit. Do not use in production systems without independent review.

---

## Repository Layout

```
go-zkp-proofs/
├── schnorr/
│   ├── schnorr.go              Schnorr equality proof
│   └── schnorr_test.go
│
└── chaum_pedersen/             (package: chaumPedersen)
    ├── pedersen_equality.go    Pedersen–Pedersen equality proof
    ├── pedersen_equality_test.go
    ├── pedersen_elgamal_equality.go    Pedersen–ElGamal equality proof
    └── pedersen_elgamal_equality_test.go
```

---

## Further Reading

### Schnorr proofs

- [**Schnorr Signature — Wikipedia**](https://en.wikipedia.org/wiki/Schnorr_signature) — accessible introduction to the scheme, its history, and why its patent expiry in 2008 opened the door to widespread adoption.
- [**Schnorr Protocol: The Foundation of ZK Proofs** — Medium](https://medium.com/@aannkkiittaa/schnorr-protocol-the-foundation-of-zk-proofs-98be2fbbe54a) — step-by-step walkthrough of the sigma protocol and how it underlies EdDSA, Bitcoin Taproot, and zkSNARKs.
- [**What Do Schnorr Signatures Do for Bitcoin?** — River](https://river.com/learn/what-are-schnorr-signatures/) — practical explanation of signature aggregation, MuSig2, and Taproot.
- [**A Literature Review of the Schnorr Identification Protocol** — Michael Straka](https://www.michaelstraka.com/schnorrlit) — academic survey of the identification protocol, its security proofs, and extensions.

### Chaum-Pedersen proofs

- [**Meet the Chaum-Pedersen Non-Interactive Zero-Knowledge Proof Method** — Medium / A Security Site](https://medium.com/asecuritysite-when-bob-met-alice/to-the-builders-of-our-future-meet-the-chaum-pedersen-non-interactive-zero-knowledge-proof-method-9846dee47fbc) — the article that inspired this library; explains the protocol intuitively with discrete-log and elliptic-curve examples.
- [**Building a Verifiable Mix-Net: ElGamal, Chaum-Pedersen and NIZK Proofs** — Medium](https://chetanramdhary.medium.com/building-a-verifiable-mix-net-elgamal-chaum-pedersen-and-nizk-proofs-6c99eab9b61d) — hands-on walkthrough implementing a mix-net for e-voting using the Pedersen–ElGamal variant in this library.
- [**Wallet Databases with Observers** — Chaum & Pedersen, 1992](https://link.springer.com/chapter/10.1007/3-540-48071-4_7) — the original academic paper (CRYPTO '92).

### General ZKP background

- [**ZKProof Community Reference** — zkproof.org](https://docs.zkproof.org) — community-maintained reference covering proof systems, applications, and standardisation efforts.
- [**Proofs, Arguments, and Zero-Knowledge** — Justin Thaler](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf) — free textbook covering the theoretical foundations of all proof systems, from sigma protocols to SNARKs.

---

## Related

- [go-bulletproofs](https://github.com/andrea-nonali/go-bulletproofs) — BulletProofs range proofs on secp256k1 (single and multi-value, inner-product argument)**
