package chaum_pedersen

import (
	"crypto/sha256"
	"math/big"

	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"

	"github.com/bwesterb/go-ristretto"
)

type PedersenEquality struct {
	h, C3, C4 				*ristretto.Point
	challenge, Z1, Z2, Z3 	*ristretto.Scalar
}

func (p *PedersenEquality) Prove(H *ristretto.Point, m, r1, r2 *ristretto.Scalar) *PedersenEquality{
	C1 := pedersen.CommitTo(H, m, r1)
	C2 := pedersen.CommitTo(H, m, r2)
	p.h = H

	var r3, r4, r5 ristretto.Scalar
	r3.Rand(); r4.Rand(); r5.Rand()

	p.C3 = pedersen.CommitTo(H, &r3, &r4)
	p.C4 = pedersen.CommitTo(H, &r3, &r5)

	var challengeScalar ristretto.Scalar
	challenge := sha256.New()
	challenge.Write([]byte(C1.String() + C2.String() + p.C3.String() + p.C4.String()))
	p.challenge = challengeScalar.SetBigInt(new(big.Int).SetBytes(challenge.Sum(nil)))

	var z1, cm ristretto.Scalar
	cm.Mul(p.challenge, m)
	p.Z1 = z1.Add(&cm, &r3)

	var z2, cr1 ristretto.Scalar
	cr1.Mul(p.challenge, r1)
	p.Z2 = z2.Add(&cr1, &r4)

	var z3, cr2 ristretto.Scalar
	cr2.Mul(p.challenge, r2)
	p.Z3 = z3.Add(&cr2, &r5)

	return p
}

func (p PedersenEquality) Verify(C1, C2 *ristretto.Point) bool {
	var cC1, C3cC1 ristretto.Point
	cC1.ScalarMult(C1, p.challenge)
	C3cC1.Add(p.C3, &cC1)

	var z1G, z2H, z1Gz2H ristretto.Point
	z1G.ScalarMultBase(p.Z1)
	z2H.ScalarMult(p.h, p.Z2)
	z1Gz2H.Add(&z1G, &z2H)

	var cC2, C4cC2 ristretto.Point
	cC2.ScalarMult(C2, p.challenge)
	C4cC2.Add(p.C4, &cC2)

	var z3H, z1Gz3H ristretto.Point
	z3H.ScalarMult(p.h, p.Z3)
	z1Gz3H.Add(&z1G, &z3H)

	return C3cC1.Equals(&z1Gz2H) && C4cC2.Equals(&z1Gz3H)
}