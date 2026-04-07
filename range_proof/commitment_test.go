package bp

import (
	"math/big"
	"testing"
)

func TestVectorPCommit(t *testing.T) {
	EC = NewECPrimeGroupKey(3)

	v := []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2)}
	output, r := VectorPCommit(v)

	if len(r) != 3 {
		t.Fatalf("VectorPCommit returned %d blinding values, want 3", len(r))
	}

	// Verify by recomputing the commitment manually.
	GVal := EC.BPG[0].Mult(v[0]).Add(EC.BPG[1].Mult(v[1]).Add(EC.BPG[2].Mult(v[2])))
	HVal := EC.BPH[0].Mult(r[0]).Add(EC.BPH[1].Mult(r[1]).Add(EC.BPH[2].Mult(r[2])))
	expected := GVal.Add(HVal)

	if !output.Equal(expected) {
		t.Error("VectorPCommit output does not match manually computed commitment")
	}
}
