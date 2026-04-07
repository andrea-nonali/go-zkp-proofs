package bp

import (
	"math/big"
	"testing"
)

func mustMRPProve(t *testing.T, values []*big.Int) MultiRangeProof {
	t.Helper()
	proof, err := MRPProve(values)
	if err != nil {
		t.Fatalf("MRPProve returned unexpected error: %v", err)
	}
	return proof
}

func TestMultiRPVerify4Values(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	if !MRPVerify(mustMRPProve(t, values)) {
		t.Error("multi-range proof for 4 zero values failed verification")
	}
}

func TestMultiRPVerify1Value(t *testing.T) {
	values := []*big.Int{big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	if !MRPVerify(mustMRPProve(t, values)) {
		t.Error("multi-range proof for single value failed verification")
	}
}

func TestMultiRPVerify2Values(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(1)}
	EC = NewECPrimeGroupKey(64 * len(values))
	if !MRPVerify(mustMRPProve(t, values)) {
		t.Error("multi-range proof for 2 values failed verification")
	}
}

func TestMultiRPVerifyVariousSizes(t *testing.T) {
	for j := 1; j < 33; j *= 2 {
		values := make([]*big.Int, j)
		for k := range values {
			values[k] = big.NewInt(0)
		}
		EC = NewECPrimeGroupKey(64 * len(values))
		if !MRPVerify(mustMRPProve(t, values)) {
			t.Errorf("multi-range proof for %d values failed verification", j)
		}
	}
}

func TestMRPProveRejectsNegative(t *testing.T) {
	values := []*big.Int{big.NewInt(-1), big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	_, err := MRPProve(values)
	if err == nil {
		t.Error("MRPProve should return an error for negative values")
	}
}
