package bp

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// MultiRangeProof is an aggregated BulletProofs proof that m committed values
// v₀, …, v_{m-1} each lie in [0, 2^(EC.V/m)). It is more efficient than m
// independent range proofs because the inner-product argument is shared.
type MultiRangeProof struct {
	Comms []ECPoint // Pedersen commitments Vⱼ = vⱼ·G + γⱼ·H
	A     ECPoint
	S     ECPoint
	T1    ECPoint
	T2    ECPoint
	Tau   *big.Int
	Th    *big.Int
	Mu    *big.Int
	IPP   InnerProdArg

	// Fiat-Shamir challenges
	Cy *big.Int
	Cz *big.Int
	Cx *big.Int
}

// CalculateLMRP computes the l(x) vector for the multi-range proof:
//
//	l(x) = (aL − z·1^(m·n)) + sL·x
func CalculateLMRP(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)
	return VectorAdd(tmp1, tmp2)
}

// CalculateRMRP computes the r(x) vector for the multi-range proof:
//
//	r(x) = yⁿ ∘ (aR + z·1^(m·n) + sR·x) + zTimesTwo
func CalculateRMRP(aR, sR, y, zTimesTwo []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(zTimesTwo) {
		panic(fmt.Sprintf(
			"CalculateRMRP: length mismatch: len(aR)=%d len(sR)=%d len(y)=%d len(zTimesTwo)=%d",
			len(aR), len(sR), len(y), len(zTimesTwo),
		))
	}

	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))
	return VectorAdd(tmp1, zTimesTwo)
}

// DeltaMRP computes the δ(y, z) term for the multi-range proof:
//
//	δ(y, z) = (z − z²)·<1^(m·n), yⁿ> − Σⱼ z^(3+j)·<1ⁿ, 2ⁿ>
func DeltaMRP(y []*big.Int, z *big.Int, m int) *big.Int {
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	// <1ⁿ, 2ⁿ> = 2ⁿ − 1
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V/m)), EC.N), big.NewInt(1))
	t3 := big.NewInt(0)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(3+int64(j)), EC.N)
		tmp1 := new(big.Int).Mod(new(big.Int).Mul(zp, po2sum), EC.N)
		t3 = new(big.Int).Mod(new(big.Int).Add(t3, tmp1), EC.N)
	}

	return new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)
}

// MRPProve generates an aggregated range proof for all values in the slice.
// Each value must lie in [0, 2^(EC.V/m)) where m = len(values).
//
// It returns an error if any value is negative or exceeds the per-value range.
func MRPProve(values []*big.Int) (MultiRangeProof, error) {
	m := len(values)
	bitsPerValue := EC.V / m
	upperBound := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitsPerValue)), EC.N)

	MRPResult := MultiRangeProof{}
	PowerOfTwos := PowerVector(bitsPerValue, big.NewInt(2))

	Comms := make([]ECPoint, m)
	gammas := make([]*big.Int, m)
	aLConcat := make([]*big.Int, EC.V)
	aRConcat := make([]*big.Int, EC.V)

	for j, v := range values {
		if v.Sign() < 0 {
			return MultiRangeProof{}, fmt.Errorf("multi range proof: value[%d] is negative", j)
		}
		if v.Cmp(upperBound) > 0 {
			return MultiRangeProof{}, errors.New("multi range proof: value exceeds per-value range")
		}

		gamma, err := rand.Int(rand.Reader, EC.N)
		check(err)
		Comms[j] = EC.G.Mult(v).Add(EC.H.Mult(gamma))
		gammas[j] = gamma

		aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", bitsPerValue)))
		aR := VectorAddScalar(aL, big.NewInt(-1))
		for i := range aR {
			aLConcat[bitsPerValue*j+i] = aL[i]
			aRConcat[bitsPerValue*j+i] = aR[i]
		}
	}

	MRPResult.Comms = Comms

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)
	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aLConcat, aRConcat).Add(EC.H.Mult(alpha))
	MRPResult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)
	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	MRPResult.S = S

	// Fiat-Shamir challenges
	chal1 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1[:])
	MRPResult.Cy = cy

	chal2 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2[:])
	MRPResult.Cz = cz

	// Build the z-powers × 2-powers vector
	zPowersTimesTwoVec := make([]*big.Int, EC.V)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		for i := 0; i < bitsPerValue; i++ {
			zPowersTimesTwoVec[j*bitsPerValue+i] = new(big.Int).Mod(new(big.Int).Mul(PowerOfTwos[i], zp), EC.N)
		}
	}

	PowerOfCY := PowerVector(EC.V, cy)
	l0 := VectorAddScalar(aLConcat, new(big.Int).Neg(cz))
	l1 := sL
	r0 := VectorAdd(
		VectorHadamard(PowerOfCY, VectorAddScalar(aRConcat, cz)),
		zPowersTimesTwoVec,
	)
	r1 := VectorHadamard(sR, PowerOfCY)

	// t0 = Σⱼ z^j · vⱼ · z² + δ(y, z)
	vz2 := big.NewInt(0)
	z2 := new(big.Int).Mod(new(big.Int).Mul(cz, cz), EC.N)
	PowerOfCZ := PowerVector(m, cz)
	for j := 0; j < m; j++ {
		vz2 = new(big.Int).Mod(
			new(big.Int).Add(vz2, new(big.Int).Mul(PowerOfCZ[j], new(big.Int).Mul(values[j], z2))),
			EC.N,
		)
	}
	t0 := new(big.Int).Mod(new(big.Int).Add(vz2, DeltaMRP(PowerOfCY, cz, m)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(l1, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(l1, r1)

	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1))
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2))
	MRPResult.T1 = T1
	MRPResult.T2 = T2

	chal3 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3[:])
	MRPResult.Cx = cx

	left := CalculateLMRP(aLConcat, sL, cz, cx)
	right := CalculateRMRP(aRConcat, sR, PowerOfCY, zPowersTimesTwoVec, cz, cx)

	thatPrime := new(big.Int).Mod(
		new(big.Int).Add(t0, new(big.Int).Add(
			new(big.Int).Mul(t1, cx),
			new(big.Int).Mul(new(big.Int).Mul(cx, cx), t2),
		)), EC.N)
	MRPResult.Th = thatPrime

	vecRandomnessTotal := big.NewInt(0)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		vecRandomnessTotal = new(big.Int).Mod(
			new(big.Int).Add(vecRandomnessTotal, new(big.Int).Mul(gammas[j], zp)),
			EC.N,
		)
	}
	taux := new(big.Int).Mod(new(big.Int).Add(
		new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N),
		new(big.Int).Add(
			new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N),
			vecRandomnessTotal,
		),
	), EC.N)
	MRPResult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	MRPResult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))
	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	MRPResult.IPP = InnerProductProve(left, right, thatPrime, P, EC.U, EC.BPG, HPrime)

	return MRPResult, nil
}

// MRPVerify verifies a multi-range proof mrp. It returns true if and only if
// all committed values lie within their respective ranges.
func MRPVerify(mrp MultiRangeProof) bool {
	m := len(mrp.Comms)
	bitsPerValue := EC.V / m

	// Recompute and validate each Fiat-Shamir challenge.
	chal1 := sha256.Sum256([]byte(mrp.A.X.String() + mrp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1[:])
	if cy.Cmp(mrp.Cy) != 0 {
		return false
	}

	chal2 := sha256.Sum256([]byte(mrp.S.X.String() + mrp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2[:])
	if cz.Cmp(mrp.Cz) != 0 {
		return false
	}

	chal3 := sha256.Sum256([]byte(mrp.T1.X.String() + mrp.T1.Y.String() + mrp.T2.X.String() + mrp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3[:])
	if cx.Cmp(mrp.Cx) != 0 {
		return false
	}

	PowersOfY := PowerVector(EC.V, cy)

	// Verify: t̂·G + τ·H == Σⱼ z^(2+j)·Vⱼ + δ(y,z)·G + x·T1 + x²·T2
	lhs := EC.G.Mult(mrp.Th).Add(EC.H.Mult(mrp.Tau))

	CommPowers := EC.Zero()
	PowersOfZ := PowerVector(m, cz)
	z2 := new(big.Int).Mod(new(big.Int).Mul(cz, cz), EC.N)
	for j := 0; j < m; j++ {
		CommPowers = CommPowers.Add(mrp.Comms[j].Mult(new(big.Int).Mul(z2, PowersOfZ[j])))
	}

	rhs := EC.G.Mult(DeltaMRP(PowersOfY, cz, m)).Add(
		mrp.T1.Mult(cx)).Add(
		mrp.T2.Mult(new(big.Int).Mul(cx, cx))).Add(CommPowers)

	if !lhs.Equal(rhs) {
		return false
	}

	// Reconstruct the inner-product commitment P and verify the IPA.
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	tmp1 := EC.Zero()
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(bitsPerValue, big.NewInt(2))
	HPrime := make([]ECPoint, len(EC.BPH))
	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowersOfY[i], EC.N))
	}

	tmp2 := EC.Zero()
	for j := 0; j < m; j++ {
		for i := 0; i < bitsPerValue; i++ {
			val1 := new(big.Int).Mul(cz, PowersOfY[j*bitsPerValue+i])
			zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
			val2 := new(big.Int).Mod(new(big.Int).Mul(zp, PowerOfTwos[i]), EC.N)
			tmp2 = tmp2.Add(HPrime[j*bitsPerValue+i].Mult(new(big.Int).Add(val1, val2)))
		}
	}

	P := mrp.A.Add(mrp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(mrp.Mu).Neg())

	return InnerProductVerifyFast(mrp.Th, P, EC.U, EC.BPG, HPrime, mrp.IPP)
}
