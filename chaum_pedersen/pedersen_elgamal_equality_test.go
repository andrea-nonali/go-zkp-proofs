package chaum_pedersen

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/tuhoag/elliptic-curve-cryptography-go/elgamal"
	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
)

func TestSuccessfulProofOnEqualCommitAndElgamalCyphertext(t *testing.T) {
	var r, m1, m2 ristretto.Scalar
	var mG, PK ristretto.Point
	r.Rand()
	m1.Rand()
	m2.Set(&m1)
	mG.ScalarMultBase(&m1)
	PK.Rand()
	e1, e2 := elgamal.Encrypt(&r, &mG, &PK)

	var H ristretto.Point
	H.Rand()
	C := pedersen.CommitTo(&H, &m2, &r)

	var proof PedersenElgamalEquality
	proof.Prove(&H, &PK, &m1, &r)

	verified := proof.Verify(C, e1, e2)
	if verified == false {
		t.Errorf("Chaum Pedersen proof is not verified, but commitments are equal")
	}
}

func TestFailingProofOnDifferentCommitAndElgamalCyphertext(t *testing.T) {
	var r, m1, m2 ristretto.Scalar
	var mG, PK ristretto.Point
	r.Rand()
	m1.Rand()
	m2.Rand()
	mG.ScalarMultBase(&m1)
	PK.Rand()
	e1, e2 := elgamal.Encrypt(&r, &mG, &PK)

	var H ristretto.Point
	H.Rand()
	C := pedersen.CommitTo(&H, &m2, &r)

	var proof PedersenElgamalEquality
	proof.Prove(&H, &PK, &m1, &r)

	verified := proof.Verify(C, e1, e2)
	if verified == true {
		t.Errorf("Chaum Pedersen proof is verified, but commitments are different")
	}
}