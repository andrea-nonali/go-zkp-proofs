package chaumPedersen

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
)

func TestPedersenElgamalEqualityProofSucceeds(t *testing.T) {
	var r, m ristretto.Scalar
	var mG, PK ristretto.Point
	r.Rand()
	m.Rand()
	mG.ScalarMultBase(&m)
	PK.Rand()
	e1, e2 := encryptElGamal(&r, &mG, &PK)

	var H ristretto.Point
	H.Rand()
	C := commitTo(&H, &m, &r)

	var proof PedersenElgamalEquality
	proof.Prove(&H, &PK, &m, &r)

	if !proof.Verify(C, e1, e2) {
		t.Error("Chaum-Pedersen proof rejected, but commitment and ciphertext encode the same message")
	}
}

func TestPedersenElgamalEqualityProofFailsOnDifferentMessages(t *testing.T) {
	var r, m1, m2 ristretto.Scalar
	var mG, PK ristretto.Point
	r.Rand()
	m1.Rand()
	m2.Rand() // independent; astronomically unlikely to equal m1
	mG.ScalarMultBase(&m1)
	PK.Rand()
	e1, e2 := encryptElGamal(&r, &mG, &PK)

	var H ristretto.Point
	H.Rand()
	// C commits to m2, but the proof is built for m1.
	C := commitTo(&H, &m2, &r)

	var proof PedersenElgamalEquality
	proof.Prove(&H, &PK, &m1, &r)

	if proof.Verify(C, e1, e2) {
		t.Error("Chaum-Pedersen proof accepted, but commitment and ciphertext encode different messages")
	}
}
