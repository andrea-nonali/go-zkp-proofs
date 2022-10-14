package schnorr

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
)

func TestSuccessfulSchnorrProofOnEqualCommits(t *testing.T) {
	// C1 = m1*G + r1H --- C2 = m2*G + r2H.
	var H ristretto.Point
	H.Rand(); 
	var m1, m2 ristretto.Scalar
	m1.Rand(); m2.Set(&m1);
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)
	var C ristretto.Point
	C.Sub(C1, C2)

	var proof SchnorrProof
	proof.PedersenEqualityProof(&H, &m1, r1, &m2, r2)
	verified := proof.Verify(&C, &H)

	if verified == false {
		t.Errorf("Schnorr proof is not verified, but commitments are equal")
	}
}

func TestFailinglSchnorrProofOnDifferentCommits(t *testing.T) {
	// C1 = m1*G + r1H --- C2 = m2*G + r2H.
	var H ristretto.Point
	H.Rand(); 
	var m1, m2 ristretto.Scalar
	m1.Rand(); m2.Set(&m1);
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)
	var C ristretto.Point
	C.Sub(C1, C2)

	var proof SchnorrProof
	proof.PedersenEqualityProof(&H, &m1, r1, &m2, r2)
	verified := proof.Verify(&C, &H)

	if verified == false {
		t.Errorf("Schnorr proof is not verified, but commitments are equal")
	}
}

func generateCommitment(H *ristretto.Point, m *ristretto.Scalar) (*ristretto.Point, *ristretto.Scalar) {
	var r ristretto.Scalar
	r.Rand()
	
	C := pedersen.CommitTo(H, m, &r)

	return C, &r
}