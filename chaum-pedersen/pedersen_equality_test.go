package chaum_pedersen

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
)

func TestSuccessfulProofOnEqualCommits(t *testing.T) {
	var H ristretto.Point
	H.Rand(); 
	var m1, m2 ristretto.Scalar
	m1.Rand()
	m2.Set(&m1)
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)

	var proof PedersenEquality
	proof.Prove(&H, &m1, r1, r2)

	verified := proof.Verify(C1, C2)
	if verified == false {
		t.Errorf("Chaum Pedersen proof is not verified, but commitments are equal")
	}
}

func TestFailingProofOnDifferentCommits(t *testing.T) {
	var H ristretto.Point
	H.Rand(); 
	var m1, m2 ristretto.Scalar
	m1.Rand(); m2.Rand()
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)

	if(C1.Equals(C2)){
		t.Errorf("Commitments are equal, there is a possible collision")
	}

	var proof PedersenEquality
	proof.Prove(&H, &m1, r1, r2)

	verified := proof.Verify(C1, C2)
	if verified == true {
		t.Errorf("Chaum Pedersen proof is verified, but commitments are different")
	}
}

func generateCommitment(H *ristretto.Point, m *ristretto.Scalar) (*ristretto.Point, *ristretto.Scalar) {
	var r ristretto.Scalar
	r.Rand()
	
	C := pedersen.CommitTo(H, m, &r)

	return C, &r
}