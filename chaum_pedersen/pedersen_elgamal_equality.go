package chaum_pedersen

import (
	"crypto/sha256"
	"math/big"

	"github.com/tuhoag/elliptic-curve-cryptography-go/elgamal"
	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"

	"github.com/bwesterb/go-ristretto"
)

type PedersenElgamalEquality struct {
	h, PK, C1, E1, E2		*ristretto.Point
	challenge, Z1, Z2	*ristretto.Scalar
}

func (pe *PedersenElgamalEquality) Prove(H, PK *ristretto.Point, m, r *ristretto.Scalar) *PedersenElgamalEquality{
	var mG ristretto.Point
	mG.ScalarMultBase(m)
	e1, e2 := elgamal.Encrypt(r, &mG, PK)
	pe.PK = PK
	C := pedersen.CommitTo(H, m, r)
	pe.h = H
	
	var r1, r2 ristretto.Scalar
	r1.Rand(); r2.Rand()

	var r1G ristretto.Point
	r1G.ScalarMultBase(&r1)
	pe.E1, pe.E2 = elgamal.Encrypt(&r2, &r1G, PK)

	pe.C1 = pedersen.CommitTo(H, &r1, &r2)

	var challengeScalar ristretto.Scalar
	challenge := sha256.New()
	challenge.Write([]byte(C.String() + e1.String() + e2.String() + pe.C1.String() + pe.E1.String() + pe.E2.String()))
	pe.challenge = challengeScalar.SetBigInt(new(big.Int).SetBytes(challenge.Sum(nil)))

	var z1, cm ristretto.Scalar
	cm.Mul(pe.challenge, m)
	pe.Z1 = z1.Add(&cm, &r1)

	var z2, cr ristretto.Scalar
	cr.Mul(pe.challenge, r)
	pe.Z2 = z2.Add(&cr, &r2)

	return pe
}

func (pe *PedersenElgamalEquality) Verify(C, e1, e2 *ristretto.Point) bool{
	var cC, C1cC ristretto.Point
	cC.ScalarMult(C, pe.challenge)
	C1cC.Add(pe.C1, &cC)

	var z1G, z2H, z1Gz2H ristretto.Point
	z1G.ScalarMultBase(pe.Z1)
	z2H.ScalarMult(pe.h, pe.Z2)
	z1Gz2H.Add(&z1G, &z2H)

	var ce1, ce2, ce1E1, ce1E2 ristretto.Point
	ce1.ScalarMult(e1, pe.challenge)
	ce2.ScalarMult(e2, pe.challenge)
	ce1E1.Add(&ce1, pe.E1)
	ce1E2.Add(&ce2, pe.E2)
	var z2G, z2PK, z2PKz1G ristretto.Point
	z2G.ScalarMultBase(pe.Z2)
	z2PK.ScalarMult(pe.PK, pe.Z2)
	z2PKz1G.Add(&z1G, &z2PK)

	return C1cC.Equals(&z1Gz2H) && ce1E1.Equals(&z2G) && ce1E2.Equals(&z2PKz1G)
}