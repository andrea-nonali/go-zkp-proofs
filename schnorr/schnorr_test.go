package schnorr

import (
	"testing"

	"github.com/bwesterb/go-ristretto"
)

func TestSchnorrProofOnEqualCommits(t *testing.T) {
	// C1 = m*G + r1*H, C2 = m*G + r2*H.
	// The proof must succeed because both commitments open to the same message m.
	var H ristretto.Point
	H.Rand()
	var m1, m2 ristretto.Scalar
	m1.Rand()
	m2.Set(&m1) // m2 == m1
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)
	var C ristretto.Point
	C.Sub(C1, C2)

	var proof SchnorrProof
	proof.Prove(&H, &m1, r1, &m2, r2)
	if !proof.Verify(&C, &H) {
		t.Error("Schnorr proof rejected, but both commitments open to the same message")
	}
}

func TestSchnorrProofFailsOnDifferentCommits(t *testing.T) {
	// C1 = m1*G + r1*H, C2 = m2*G + r2*H with m1 != m2.
	// The proof must be rejected because the messages are different.
	var H ristretto.Point
	H.Rand()
	var m1, m2 ristretto.Scalar
	m1.Rand()
	m2.Rand() // independent random scalar; astronomically unlikely to equal m1
	C1, r1 := generateCommitment(&H, &m1)
	C2, r2 := generateCommitment(&H, &m2)
	var C ristretto.Point
	C.Sub(C1, C2)

	var proof SchnorrProof
	proof.Prove(&H, &m1, r1, &m2, r2)
	if proof.Verify(&C, &H) {
		t.Error("Schnorr proof accepted, but commitments open to different messages")
	}
}

func generateCommitment(H *ristretto.Point, m *ristretto.Scalar) (*ristretto.Point, *ristretto.Scalar) {
	var r ristretto.Scalar
	r.Rand()
	var mG, rH ristretto.Point
	mG.ScalarMultBase(m)
	rH.ScalarMult(H, &r)
	C := new(ristretto.Point).Add(&mG, &rH)
	return C, &r
}
