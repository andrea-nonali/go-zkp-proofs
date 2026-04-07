package bp

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// RangeProof is a BulletProofs proof that a committed value v lies in the range
// [0, 2^n) where n = EC.V. The commitment Comm = v·G + γ·H is included in the
// proof so the verifier can check it without knowing v or γ.
type RangeProof struct {
	Comm ECPoint  // Pedersen commitment to the proved value
	A    ECPoint  // commitment to the bit-decomposition of v
	S    ECPoint  // commitment to the blinding vectors sL, sR
	T1   ECPoint  // commitment to the coefficient t1 of the t-polynomial
	T2   ECPoint  // commitment to the coefficient t2 of the t-polynomial
	Tau  *big.Int // blinding factor for the t-polynomial evaluation
	Th   *big.Int // evaluation t̂ = <l(x), r(x)>
	Mu   *big.Int // blinding factor combining α and ρ

	IPP InnerProdArg // inner-product argument for <l, r> = t̂

	// Fiat-Shamir challenges (stored so the verifier can check consistency)
	Cy *big.Int
	Cz *big.Int
	Cx *big.Int
}

// Delta computes the δ(y, z) term used in both RPProve and RPVerify:
//
//	δ(y, z) = (z − z²)·<1ⁿ, yⁿ> − z³·<1ⁿ, 2ⁿ>
func Delta(y []*big.Int, z *big.Int) *big.Int {
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	z3 := new(big.Int).Mod(new(big.Int).Mul(z2, z), EC.N)
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N), big.NewInt(1))
	t3 := new(big.Int).Mod(new(big.Int).Mul(z3, po2sum), EC.N)

	return new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)
}

// calculateL computes the l(x) vector: l(x) = (aL − z·1ⁿ) + sL·x.
func calculateL(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)
	return VectorAdd(tmp1, tmp2)
}

// calculateR computes the r(x) vector:
//
//	r(x) = yⁿ ∘ (aR + z·1ⁿ + sR·x) + z²·2ⁿ
func calculateR(aR, sR, y, po2 []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(po2) {
		panic(fmt.Sprintf(
			"calculateR: length mismatch: len(aR)=%d len(sR)=%d len(y)=%d len(po2)=%d",
			len(aR), len(sR), len(y), len(po2),
		))
	}

	z2 := new(big.Int).Exp(z, big.NewInt(2), EC.N)
	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))
	tmp2 := ScalarVectorMul(po2, z2)
	return VectorAdd(tmp1, tmp2)
}

// RPProve generates a range proof that the value v lies in [0, 2^EC.V).
//
// It returns an error if v is negative or exceeds the supported range.
func RPProve(v *big.Int) (RangeProof, error) {
	if v.Sign() < 0 {
		return RangeProof{}, errors.New("range proof: value is negative")
	}
	upperBound := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N)
	if v.Cmp(upperBound) > 0 {
		return RangeProof{}, fmt.Errorf("range proof: value %s exceeds maximum %s", v, upperBound)
	}

	rpresult := RangeProof{}
	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))

	gamma, err := rand.Int(rand.Reader, EC.N)
	check(err)
	rpresult.Comm = EC.G.Mult(v).Add(EC.H.Mult(gamma))

	// Bit-decompose v: aL[i] ∈ {0,1}, aR = aL − 1ⁿ
	aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", EC.V)))
	aR := VectorAddScalar(aL, big.NewInt(-1))

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)
	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aL, aR).Add(EC.H.Mult(alpha))
	rpresult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)
	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	rpresult.S = S

	// Fiat-Shamir challenges
	chal1 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1[:])
	rpresult.Cy = cy

	chal2 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2[:])
	rpresult.Cz = cz

	z2 := new(big.Int).Exp(cz, big.NewInt(2), EC.N)
	PowerOfCY := PowerVector(EC.V, cy)

	l0 := VectorAddScalar(aL, new(big.Int).Neg(cz))
	r0 := VectorAdd(
		VectorHadamard(PowerOfCY, VectorAddScalar(aR, cz)),
		ScalarVectorMul(PowerOfTwos, z2),
	)
	r1 := VectorHadamard(sR, PowerOfCY)

	t0 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(v, z2), Delta(PowerOfCY, cz)), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(sL, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(sL, r1)

	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1))
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2))
	rpresult.T1 = T1
	rpresult.T2 = T2

	chal3 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3[:])
	rpresult.Cx = cx

	left := calculateL(aL, sL, cz, cx)
	right := calculateR(aR, sR, PowerOfCY, PowerOfTwos, cz, cx)

	thatPrime := new(big.Int).Mod(
		new(big.Int).Add(t0, new(big.Int).Add(
			new(big.Int).Mul(t1, cx),
			new(big.Int).Mul(new(big.Int).Mul(cx, cx), t2),
		)), EC.N)
	rpresult.Th = thatPrime

	taux := new(big.Int).Mod(new(big.Int).Add(
		new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N),
		new(big.Int).Add(
			new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N),
			new(big.Int).Mod(new(big.Int).Mul(z2, gamma), EC.N),
		),
	), EC.N)
	rpresult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	rpresult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))
	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	rpresult.IPP = InnerProductProve(left, right, thatPrime, P, EC.U, EC.BPG, HPrime)

	return rpresult, nil
}

// RPVerify verifies a range proof rp. It returns true if and only if the proof
// is valid, i.e. the committed value lies in [0, 2^EC.V).
func RPVerify(rp RangeProof) bool {
	// Recompute and validate each Fiat-Shamir challenge.
	chal1 := sha256.Sum256([]byte(rp.A.X.String() + rp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1[:])
	if cy.Cmp(rp.Cy) != 0 {
		return false
	}

	chal2 := sha256.Sum256([]byte(rp.S.X.String() + rp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2[:])
	if cz.Cmp(rp.Cz) != 0 {
		return false
	}

	chal3 := sha256.Sum256([]byte(rp.T1.X.String() + rp.T1.Y.String() + rp.T2.X.String() + rp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3[:])
	if cx.Cmp(rp.Cx) != 0 {
		return false
	}

	PowersOfY := PowerVector(EC.V, cy)

	// Verify: t̂·G + τ·H == z²·V + δ(y,z)·G + x·T1 + x²·T2
	lhs := EC.G.Mult(rp.Th).Add(EC.H.Mult(rp.Tau))
	rhs := rp.Comm.Mult(new(big.Int).Mul(cz, cz)).Add(
		EC.G.Mult(Delta(PowersOfY, cz))).Add(
		rp.T1.Mult(cx)).Add(
		rp.T2.Mult(new(big.Int).Mul(cx, cx)))

	if !lhs.Equal(rhs) {
		return false
	}

	// Reconstruct the inner-product commitment P and verify the IPA.
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	tmp1 := EC.Zero()
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))
	HPrime := make([]ECPoint, len(EC.BPH))
	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowersOfY[i], EC.N))
	}

	tmp2 := EC.Zero()
	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowersOfY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	P := rp.A.Add(rp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(rp.Mu).Neg())

	return InnerProductVerifyFast(rp.Th, P, EC.U, EC.BPG, HPrime, rp.IPP)
}
