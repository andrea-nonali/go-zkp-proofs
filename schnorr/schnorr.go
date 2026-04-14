// Package schnorr implements a Schnorr-based zero-knowledge equality proof for
// Pedersen commitments.
//
// The proof convinces a verifier that two Pedersen commitments C1 and C2 (built
// over the same generator H but with independent blinding factors r1, r2) open
// to the same message m, without revealing m, r1, or r2.
//
// # Protocol sketch
//
// Given C1 = m·G + r1·H and C2 = m·G + r2·H, let C = C1 − C2 = (r1−r2)·H.
// The prover demonstrates knowledge of the discrete log of C with respect to H
// using a standard Schnorr sigma protocol made non-interactive via the
// Fiat-Shamir transform (SHA-256).
//
// # Security note
//
// The Fiat-Shamir challenge is derived by hashing the canonical 32-byte
// Ristretto encoding of each curve point, prefixed with the domain-separation
// tag "schnorr-pedersen-equality-v1". This ensures the hash input is injective
// across point tuples and isolated from other protocols sharing the same key material.
package schnorr

import (
	"crypto/sha256"
	"math/big"

	"github.com/bwesterb/go-ristretto"
)

// SchnorrProof holds the challenge scalar C and the response scalar Z produced
// by the Schnorr sigma protocol.
type SchnorrProof struct {
	C, Z *ristretto.Scalar
}

// Prove generates a Schnorr equality proof asserting that commitments
//
//	C1 = m1·G + r1·H
//	C2 = m2·G + r2·H
//
// open to the same message (m1 == m2). The method populates the receiver and
// returns it for convenience.
func (sp *SchnorrProof) Prove(H *ristretto.Point, m1, r1, m2, r2 *ristretto.Scalar) *SchnorrProof {
	// Work with C = C1 − C2 = (m1−m2)·G + (r1−r2)·H.
	var m, r ristretto.Scalar
	m.Sub(m1, m2)
	r.Sub(r1, r2)
	var mG, rH, comm ristretto.Point
	mG.ScalarMultBase(&m)
	rH.ScalarMult(H, &r)
	comm.Add(&mG, &rH)

	var rP ristretto.Scalar
	rP.Rand()

	sp.C = proofChallenge(&comm, H, &rP)
	sp.Z = proofResponse(&r, sp.C, &rP)
	return sp
}

// Verify checks the Schnorr equality proof against the commitment verifyComm,
// which the caller must compute as C1 − C2. It returns true if and only if the
// proof is valid.
func (sp *SchnorrProof) Verify(verifyComm, H *ristretto.Point) bool {
	cVer := verifyChallenge(H, verifyComm, sp)
	return sp.C.Equals(&cVer)
}

// proofChallenge computes c = SHA-256(dst ‖ C ‖ H ‖ r·H) and returns it as a scalar.
func proofChallenge(C, H *ristretto.Point, r *ristretto.Scalar) *ristretto.Scalar {
	var rH ristretto.Point
	rH.ScalarMult(H, r)

	h := sha256.New()
	h.Write([]byte("schnorr-pedersen-equality-v1"))
	h.Write(C.Bytes())
	h.Write(H.Bytes())
	h.Write(rH.Bytes())

	var c ristretto.Scalar
	c.SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))
	return &c
}

// proofResponse computes z = r·c + rP.
func proofResponse(r, c, rP *ristretto.Scalar) *ristretto.Scalar {
	var z, rc ristretto.Scalar
	rc.Mul(r, c)
	z.Add(&rc, rP)
	return &z
}

// verifyChallenge recomputes the challenge from the verifier's side as
// SHA-256(dst ‖ comm ‖ H ‖ z·H − c·comm).
func verifyChallenge(H, comm *ristretto.Point, sp *SchnorrProof) ristretto.Scalar {
	var zH, cComm, zHSubcComm ristretto.Point
	zH.ScalarMult(H, sp.Z)
	cComm.ScalarMult(comm, sp.C)
	zHSubcComm.Sub(&zH, &cComm)

	h := sha256.New()
	h.Write([]byte("schnorr-pedersen-equality-v1"))
	h.Write(comm.Bytes())
	h.Write(H.Bytes())
	h.Write(zHSubcComm.Bytes())

	var c ristretto.Scalar
	c.SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))
	return c
}
