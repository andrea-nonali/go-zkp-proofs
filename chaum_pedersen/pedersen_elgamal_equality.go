package chaumPedersen

import (
	"crypto/sha256"
	"math/big"

	"github.com/bwesterb/go-ristretto"
)

// PedersenElgamalEquality is a Chaum-Pedersen proof that a Pedersen commitment
//
//	C = m·G + r·H
//
// and an ElGamal ciphertext
//
//	(E1, E2) = ElGamal.Encrypt(r, m·G, PK)
//
// were constructed with the same plaintext message m.
type PedersenElgamalEquality struct {
	H, PK, C1, E1, E2 *ristretto.Point
	Challenge, Z1, Z2 *ristretto.Scalar
}

// Prove generates the proof that the Pedersen commitment and the ElGamal
// ciphertext derived from (H, PK, m, r) encode the same message m.
// It populates the receiver and returns it for convenience.
func (pe *PedersenElgamalEquality) Prove(H, PK *ristretto.Point, m, r *ristretto.Scalar) *PedersenElgamalEquality {
	var mG ristretto.Point
	mG.ScalarMultBase(m)
	e1, e2 := encryptElGamal(r, &mG, PK)
	pe.PK = PK
	C := commitTo(H, m, r)
	pe.H = H

	var r1, r2 ristretto.Scalar
	r1.Rand()
	r2.Rand()

	var r1G ristretto.Point
	r1G.ScalarMultBase(&r1)
	pe.E1, pe.E2 = encryptElGamal(&r2, &r1G, PK)
	pe.C1 = commitTo(H, &r1, &r2)

	h := sha256.New()
	h.Write([]byte("chaum-pedersen-elgamal-equality-v1"))
	h.Write(C.Bytes())
	h.Write(e1.Bytes())
	h.Write(e2.Bytes())
	h.Write(pe.C1.Bytes())
	h.Write(pe.E1.Bytes())
	h.Write(pe.E2.Bytes())

	var challengeScalar ristretto.Scalar
	pe.Challenge = challengeScalar.SetBigInt(new(big.Int).SetBytes(h.Sum(nil)))

	var z1, cm ristretto.Scalar
	cm.Mul(pe.Challenge, m)
	pe.Z1 = z1.Add(&cm, &r1)

	var z2, cr ristretto.Scalar
	cr.Mul(pe.Challenge, r)
	pe.Z2 = z2.Add(&cr, &r2)

	return pe
}

// Verify checks the proof against the Pedersen commitment C and the ElGamal
// ciphertext components e1, e2. It returns true if and only if the proof is
// valid.
func (pe *PedersenElgamalEquality) Verify(C, e1, e2 *ristretto.Point) bool {
	// Check: C1 + c·C == z1·G + z2·H
	var cC, C1cC ristretto.Point
	cC.ScalarMult(C, pe.Challenge)
	C1cC.Add(pe.C1, &cC)

	var z1G, z2H, z1Gz2H ristretto.Point
	z1G.ScalarMultBase(pe.Z1)
	z2H.ScalarMult(pe.H, pe.Z2)
	z1Gz2H.Add(&z1G, &z2H)

	// Check: E1 + c·e1 == z2·G
	var ce1, ce2, ce1E1, ce1E2 ristretto.Point
	ce1.ScalarMult(e1, pe.Challenge)
	ce2.ScalarMult(e2, pe.Challenge)
	ce1E1.Add(&ce1, pe.E1)
	ce1E2.Add(&ce2, pe.E2)

	var z2G, z2PK, z2PKz1G ristretto.Point
	z2G.ScalarMultBase(pe.Z2)
	z2PK.ScalarMult(pe.PK, pe.Z2)
	z2PKz1G.Add(&z1G, &z2PK)

	return C1cC.Equals(&z1Gz2H) && ce1E1.Equals(&z2G) && ce1E2.Equals(&z2PKz1G)
}

// commitTo computes the Pedersen commitment m·G + r·H.
func commitTo(H *ristretto.Point, m, r *ristretto.Scalar) *ristretto.Point {
	var mG, rH, C ristretto.Point
	mG.ScalarMultBase(m)
	rH.ScalarMult(H, r)
	C.Add(&mG, &rH)
	return &C
}

// encryptElGamal computes the ElGamal ciphertext (r·G, mG + r·PK).
func encryptElGamal(r *ristretto.Scalar, mG, PK *ristretto.Point) (*ristretto.Point, *ristretto.Point) {
	var e1, rPK, e2 ristretto.Point
	e1.ScalarMultBase(r)
	rPK.ScalarMult(PK, r)
	e2.Add(mG, &rPK)
	return &e1, &e2
}
