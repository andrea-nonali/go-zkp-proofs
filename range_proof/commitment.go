package bp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// VectorPCommit commits to a vector of values using independent random blinding
// factors per element.
//
// It returns the aggregate Pedersen commitment point and the blinding vector R
// such that commitment = Σ (value[i]·BPG[i] + R[i]·BPH[i]).
func VectorPCommit(value []*big.Int) (ECPoint, []*big.Int) {
	R := make([]*big.Int, EC.V)
	commitment := EC.Zero()

	for i := 0; i < EC.V; i++ {
		r, err := rand.Int(rand.Reader, EC.N)
		check(err)
		R[i] = r

		modValue := new(big.Int).Mod(value[i], EC.N)
		lhsX, lhsY := EC.C.ScalarMult(EC.BPG[i].X, EC.BPG[i].Y, modValue.Bytes())
		rhsX, rhsY := EC.C.ScalarMult(EC.BPH[i].X, EC.BPH[i].Y, r.Bytes())
		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment, R
}

// TwoVectorPCommit returns the commitment Σ (a[i]·BPG[i] + b[i]·BPH[i]).
// Both slices must have the same length; a length mismatch panics.
func TwoVectorPCommit(a []*big.Int, b []*big.Int) ECPoint {
	if len(a) != len(b) {
		panic(fmt.Sprintf("TwoVectorPCommit: length mismatch: len(a)=%d len(b)=%d", len(a), len(b)))
	}

	commitment := EC.Zero()
	for i := 0; i < EC.V; i++ {
		commitment = commitment.Add(EC.BPG[i].Mult(a[i])).Add(EC.BPH[i].Mult(b[i]))
	}
	return commitment
}

// TwoVectorPCommitWithGens returns the commitment Σ (a[i]·G[i] + b[i]·H[i])
// using the caller-supplied generator vectors G and H.
// All four slices must have the same length; a length mismatch panics.
func TwoVectorPCommitWithGens(G, H []ECPoint, a, b []*big.Int) ECPoint {
	if len(G) != len(H) || len(G) != len(a) || len(a) != len(b) {
		panic(fmt.Sprintf(
			"TwoVectorPCommitWithGens: length mismatch: len(G)=%d len(H)=%d len(a)=%d len(b)=%d",
			len(G), len(H), len(a), len(b),
		))
	}

	commitment := EC.Zero()
	for i := 0; i < len(G); i++ {
		modA := new(big.Int).Mod(a[i], EC.N)
		modB := new(big.Int).Mod(b[i], EC.N)
		commitment = commitment.Add(G[i].Mult(modA)).Add(H[i].Mult(modB))
	}
	return commitment
}
