package chaum_pedersen

import (
	"crypto/sha256"
	"fmt"
	"math/big"
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

func TestListProof(t *testing.T) {
	var H ristretto.Point
	H.Rand(); 
	var m1, m2, m3, m4 ristretto.Scalar
	m1.Rand()
	m2.Set(&m1)
	m3.Set(&m1)
	m4.Set(&m1)
	C1, r1 := generateCommitment(&H, &m1)
	C2, _ := generateCommitment(&H, &m2)
	C3, r3 := generateCommitment(&H, &m3)
	C4, r4 := generateCommitment(&H, &m4)

	var a1Scal, a2Scal, a3Scal, a4Scal ristretto.Scalar
	a1 := sha256.New()
	a2 := sha256.New()
	a3 := sha256.New()
	a4 := sha256.New()
	a1.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "1"))
	a2.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "2"))
	a3.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "3"))
	a4.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "4"))
	a1Scal.SetBigInt(new(big.Int).SetBytes(a1.Sum(nil)))
	a2Scal.SetBigInt(new(big.Int).SetBytes(a2.Sum(nil)))
	a3Scal.SetBigInt(new(big.Int).SetBytes(a3.Sum(nil)))
	a4Scal.SetBigInt(new(big.Int).SetBytes(a4.Sum(nil)))

	var D, D3, D4 ristretto.Point
	var C3mC1, C4mC1 ristretto.Point
	C3mC1.Sub(C3, C1)
	C4mC1.Sub(C4, C1)
	D3.ScalarMult(&C3mC1, &a3Scal)
	D4.ScalarMult(&C4mC1, &a4Scal)
	D.Add(&D3, &D4)

	var z, z3, z4 ristretto.Scalar
	var z3mz1, z4mz1 ristretto.Scalar
	z3mz1.Sub(r3, r1)
	z4mz1.Sub(r4, r1)
	z3.Mul(&a3Scal, &z3mz1)
	z4.Mul(&a4Scal, &z4mz1)
	z.Add(&z3, &z4)

	var zeroScal ristretto.Scalar
	zeroScal.SetZero()
	zeroComm := pedersen.CommitTo(&H, &zeroScal, &z)
	

	fmt.Println(D)
	fmt.Println(zeroComm)

	// d is a commitment to 0 with z as blinding factor
	
}

func TestListProofMine(t *testing.T) {
	var H ristretto.Point
	H.Rand(); 
	var m1, m2, m3, m4 ristretto.Scalar
	m1.Rand()
	m2.Set(&m1)
	m3.Set(&m1)
	m4.Set(&m1)
	C1, r1 := generateCommitment(&H, &m1)
	C2, _ := generateCommitment(&H, &m2)
	C3, r3 := generateCommitment(&H, &m3)
	C4, r4 := generateCommitment(&H, &m4)

	var a1Scal, a2Scal, a3Scal, a4Scal ristretto.Scalar
	a1 := sha256.New()
	a2 := sha256.New()
	a3 := sha256.New()
	a4 := sha256.New()
	a1.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "1"))
	a2.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "2"))
	a3.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "3"))
	a4.Write([]byte(C1.String() + C2.String() + C3.String() + C4.String() + "4"))
	a1Scal.SetBigInt(new(big.Int).SetBytes(a1.Sum(nil)))
	a2Scal.SetBigInt(new(big.Int).SetBytes(a2.Sum(nil)))
	a3Scal.SetBigInt(new(big.Int).SetBytes(a3.Sum(nil)))
	a4Scal.SetBigInt(new(big.Int).SetBytes(a4.Sum(nil)))

	var base ristretto.Point
	base.SetBase()
	var random ristretto.Point
	random.Rand()

	var D, D3, D4 ristretto.Point
	var C3mC1, C4mC1 ristretto.Point
	C3mC1.Sub(C3, C1)
	C4mC1.Sub(C4, C1)
	D3.ScalarMult(&C3mC1, &a3Scal)
	D3.Add(&D3, &base)
	D4.ScalarMult(&C4mC1, &a4Scal)
	D4.Add(&D4, &base)
	D.Add(&D3, &D4)

	var z, z3, z4 ristretto.Scalar
	var z3mz1, z4mz1 ristretto.Scalar
	z3mz1.Sub(r3, r1)
	z4mz1.Sub(r4, r1)
	z3.Mul(&a3Scal, &z3mz1)
	z4.Mul(&a4Scal, &z4mz1)
	z.Add(&z3, &z4)

	var twoScal ristretto.Scalar
	twoScal.SetUint64(2)
	twoComm := pedersen.CommitTo(&H, &twoScal, &z)
	

	fmt.Println(D)
	fmt.Println(twoComm)

	// d is a commitment to k' (2) with z as blinding factor
	
}

func generateCommitment(H *ristretto.Point, m *ristretto.Scalar) (*ristretto.Point, *ristretto.Scalar) {
	var r ristretto.Scalar
	r.Rand()
	
	C := pedersen.CommitTo(H, m, &r)

	return C, &r
}