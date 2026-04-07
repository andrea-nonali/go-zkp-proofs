package bp

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func mustRPProve(t *testing.T, v *big.Int) RangeProof {
	t.Helper()
	proof, err := RPProve(v)
	if err != nil {
		t.Fatalf("RPProve(%s) returned unexpected error: %v", v, err)
	}
	return proof
}

func TestRPVerifyZero(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	if !RPVerify(mustRPProve(t, big.NewInt(0))) {
		t.Error("range proof for 0 failed verification")
	}
}

func TestRPVerifyMaxValue(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	max := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(63), EC.N), big.NewInt(1))
	if !RPVerify(mustRPProve(t, max)) {
		t.Error("range proof for maximum in-range value failed verification")
	}
}

func TestRPVerifySmallValue(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	if !RPVerify(mustRPProve(t, big.NewInt(3))) {
		t.Error("range proof for value 3 failed verification")
	}
}

func TestRPVerify32Bit(t *testing.T) {
	EC = NewECPrimeGroupKey(32)
	if !RPVerify(mustRPProve(t, big.NewInt(0))) {
		t.Error("range proof for 0 in 32-bit range failed verification")
	}
}

func TestRPVerifyRandom(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	v, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)
	if !RPVerify(mustRPProve(t, v)) {
		t.Errorf("range proof for random value %s failed verification", v)
	}
}

func TestRPProveRejectsNegative(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	_, err := RPProve(big.NewInt(-1))
	if err == nil {
		t.Error("RPProve should return an error for negative values")
	}
}

func TestRPProveRejectsOutOfRange(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	tooBig := new(big.Int).Exp(big.NewInt(2), big.NewInt(65), nil)
	_, err := RPProve(tooBig)
	if err == nil {
		t.Error("RPProve should return an error for values above the maximum range")
	}
}
