package bp

import (
	"crypto/sha256"
	"math"
	"math/big"
)

// InnerProdArg is a logarithmic-size proof that <a, b> = c for committed
// vectors a and b. It is the core building block of the BulletProofs range
// proof.
type InnerProdArg struct {
	L          []ECPoint  // left intermediate commitment at each recursion level
	R          []ECPoint  // right intermediate commitment at each recursion level
	A          *big.Int   // final scalar a (base case)
	B          *big.Int   // final scalar b (base case)
	Challenges []*big.Int // Fiat-Shamir challenges, one per recursion level plus the initial one
}

// GenerateNewParams folds the generator vectors and the running commitment P
// using the challenge x for one recursion step of the inner-product argument.
//
// Returns the updated generator vectors G', H' and the updated commitment P'.
func GenerateNewParams(G, H []ECPoint, x *big.Int, L, R, P ECPoint) ([]ECPoint, []ECPoint, ECPoint) {
	nprime := len(G) / 2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	xinv := new(big.Int).ModInverse(x, EC.N)

	for i := range Gprime {
		Gprime[i] = G[i].Mult(xinv).Add(G[i+nprime].Mult(x))
		Hprime[i] = H[i].Mult(x).Add(H[i+nprime].Mult(xinv))
	}

	x2 := new(big.Int).Mod(new(big.Int).Mul(x, x), EC.N)
	xinv2 := new(big.Int).ModInverse(x2, EC.N)

	// P' = x²·L + P + x⁻²·R
	Pprime := L.Mult(x2).Add(P).Add(R.Mult(xinv2))

	return Gprime, Hprime, Pprime
}

// innerProductProveSub is the recursive helper for InnerProductProve. It
// accumulates intermediate L, R values into proof and returns the completed
// proof at the base case.
func innerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	if len(a) == 1 {
		proof.A = a[0]
		proof.B = b[0]
		return proof
	}

	curIt := int(math.Log2(float64(len(a)))) - 1
	nprime := len(a) / 2

	cl := InnerProduct(a[:nprime], b[nprime:])
	cr := InnerProduct(a[nprime:], b[:nprime])
	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))

	proof.L[curIt] = L
	proof.R[curIt] = R

	s256 := sha256.Sum256([]byte(
		L.X.String() + L.Y.String() +
			R.X.String() + R.Y.String()))
	x := new(big.Int).SetBytes(s256[:])
	proof.Challenges[curIt] = x

	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, L, R, P)
	xinv := new(big.Int).ModInverse(x, EC.N)

	aprime := VectorAdd(ScalarVectorMul(a[:nprime], x), ScalarVectorMul(a[nprime:], xinv))
	bprime := VectorAdd(ScalarVectorMul(b[:nprime], xinv), ScalarVectorMul(b[nprime:], x))

	return innerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

// InnerProductProve constructs a proof that <a, b> = c given commitment P and
// generators G, H. U is an auxiliary generator with unknown discrete log.
func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P, U ECPoint, G, H []ECPoint) InnerProdArg {
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Lvals := make([]ECPoint, loglen)
	Rvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		L:          Lvals,
		R:          Rvals,
		A:          big.NewInt(0),
		B:          big.NewInt(0),
		Challenges: challenges,
	}

	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	runningProof.Challenges[loglen] = new(big.Int).SetBytes(x[:])

	xScalar := new(big.Int).SetBytes(x[:])
	Pprime := P.Add(U.Mult(new(big.Int).Mul(xScalar, c)))
	ux := U.Mult(xScalar)

	return innerProductProveSub(runningProof, G, H, a, b, ux, Pprime)
}

// InnerProductVerify verifies the inner-product proof ipp against the claimed
// inner product c, commitment P, auxiliary generator U, and generator vectors
// G and H. It returns true if and only if the proof is valid.
func InnerProductVerify(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		return false
	}

	curIt--

	Gprime := G
	Hprime := H
	Pprime := P.Add(ux.Mult(c))

	for curIt >= 0 {
		Lval := ipp.L[curIt]
		Rval := ipp.R[curIt]

		s256 := sha256.Sum256([]byte(
			Lval.X.String() + Lval.Y.String() +
				Rval.X.String() + Rval.Y.String()))
		chal2 := new(big.Int).SetBytes(s256[:])

		if ipp.Challenges[curIt].Cmp(chal2) != 0 {
			return false
		}

		Gprime, Hprime, Pprime = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime)
		curIt--
	}

	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)

	Pcalc := Gprime[0].Mult(ipp.A).Add(Hprime[0].Mult(ipp.B)).Add(ux.Mult(ccalc))

	return Pprime.Equal(Pcalc)
}

// InnerProductVerifyFast is an optimised variant of InnerProductVerify that
// replaces the n separate scalar multiplications of InnerProductVerify with a
// single multi-exponentiation, reducing verification time significantly for
// large vectors.
func InnerProductVerifyFast(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		return false
	}

	for j := curIt - 1; j >= 0; j-- {
		Lval := ipp.L[j]
		Rval := ipp.R[j]

		s256 := sha256.Sum256([]byte(
			Lval.X.String() + Lval.Y.String() +
				Rval.X.String() + Rval.Y.String()))
		chal2 := new(big.Int).SetBytes(s256[:])

		if ipp.Challenges[j].Cmp(chal2) != 0 {
			return false
		}
	}

	curIt--
	Pprime := P.Add(ux.Mult(c))

	tmp1 := EC.Zero()
	for j := curIt; j >= 0; j-- {
		x2 := new(big.Int).Exp(ipp.Challenges[j], big.NewInt(2), EC.N)
		x2i := new(big.Int).ModInverse(x2, EC.N)
		tmp1 = ipp.L[j].Mult(x2).Add(ipp.R[j].Mult(x2i)).Add(tmp1)
	}
	rhs := Pprime.Add(tmp1)

	sScalars := make([]*big.Int, EC.V)
	invsScalars := make([]*big.Int, EC.V)

	for i := 0; i < EC.V; i++ {
		si := big.NewInt(1)
		for j := curIt; j >= 0; j-- {
			chal := ipp.Challenges[j]
			if big.NewInt(int64(i)).Bit(j) == 0 {
				chal = new(big.Int).ModInverse(chal, EC.N)
			}
			si = new(big.Int).Mod(new(big.Int).Mul(si, chal), EC.N)
		}
		sScalars[i] = si
		invsScalars[i] = new(big.Int).ModInverse(si, EC.N)
	}

	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)
	lhs := TwoVectorPCommitWithGens(G, H, ScalarVectorMul(sScalars, ipp.A), ScalarVectorMul(invsScalars, ipp.B)).Add(ux.Mult(ccalc))

	return rhs.Equal(lhs)
}
