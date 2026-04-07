package chaumPedersen

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"
)

func TestPedersenEqualityProofSucceeds(t *testing.T) {
	var H ristretto.Point
	H.Rand()
	var m ristretto.Scalar
	m.Rand()
	C1, r1 := generateCommitment(&H, &m)
	C2, r2 := generateCommitment(&H, &m)

	var proof PedersenEquality
	proof.Prove(&H, &m, r1, r2)

	if !proof.Verify(C1, C2) {
		t.Error("Chaum-Pedersen proof rejected, but both commitments open to the same message")
	}
}

func TestPedersenEqualityProofFailsOnDifferentMessages(t *testing.T) {
	var H ristretto.Point
	H.Rand()
	var m1, m2 ristretto.Scalar
	m1.Rand()
	m2.Rand() // independent; astronomically unlikely to equal m1
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)

	// Sanity check: commitments must differ for the test to be meaningful.
	if C1.Equals(C2) {
		t.Fatal("unexpected collision between two independent random commitments")
	}

	var proof PedersenEquality
	proof.Prove(&H, &m1, r1, r2) // proof is for m1, but C2 commits to m2

	if proof.Verify(C1, C2) {
		t.Error("Chaum-Pedersen proof accepted, but commitments open to different messages")
	}
}

func generateCommitment(H *ristretto.Point, m *ristretto.Scalar) (*ristretto.Point, *ristretto.Scalar) {
	var r ristretto.Scalar
	r.Rand()
	C := pedersen.CommitTo(H, m, &r)
	return C, &r
}
