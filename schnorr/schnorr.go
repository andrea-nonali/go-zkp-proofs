package schnorr

import (
	"crypto/sha256"
	"math/big"

	"github.com/tuhoag/elliptic-curve-cryptography-go/pedersen"

	"github.com/bwesterb/go-ristretto"
)

type SchnorrProof struct {
	C, Z *ristretto.Scalar
}

func (sp *SchnorrProof) PedersenEqualityProof(H *ristretto.Point, m1, r1, m2, r2 *ristretto.Scalar) *SchnorrProof{
	// C = C1 - C2
	var m, r ristretto.Scalar
	m.Sub(m1, m2); r.Sub(r1, r2)
	comm := pedersen.CommitTo(H, &m, &r)

	//random sample
	var rP ristretto.Scalar
	rP.Rand()
	//c = Hash(C,H,rH)
	sp.C = getProofHash(comm, H, &rP)
	// z = mc + r mod p
	sp.Z = getProofZ(&r, sp.C, &rP)

	return sp
}

func (sp SchnorrProof) Verify(verifyComm, H *ristretto.Point) bool {
	// Hash(C, H, sp.z*H − sp.c*C)
	cVer := getVerifyHash(H, verifyComm, sp)

	equals := sp.C.Equals(&cVer)

	return equals
}

func getProofHash(C, H *ristretto.Point, r *ristretto.Scalar) *ristretto.Scalar {
	var cScal ristretto.Scalar

	var rH ristretto.Point
	rH.ScalarMult(H, r)
	c := sha256.New()
	c.Write([]byte(C.String() + H.String() + rH.String()))
	cScal.SetBigInt(new(big.Int).SetBytes(c.Sum(nil)))

	return &cScal
}

func getProofZ(m, c, r *ristretto.Scalar) *ristretto.Scalar{
	var z, mc ristretto.Scalar
	mc.Mul(m, c)
	z.Add(&mc, r)
	return &z
}

func getVerifyHash(H, comm *ristretto.Point, sp SchnorrProof) ristretto.Scalar {
	var cScal ristretto.Scalar
	
	var zH, cC, zHMincC ristretto.Point
	zH.ScalarMult(H, sp.Z)
	cC.ScalarMult(comm, sp.C)
	zHMincC.Sub(&zH, &cC)

	c := sha256.New()
	c.Write([]byte(comm.String() + H.String() + zHMincC.String()))
	cScal.SetBigInt(new(big.Int).SetBytes(c.Sum(nil)))

	return cScal
}