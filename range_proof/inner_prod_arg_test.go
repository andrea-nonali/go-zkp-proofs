package bp

import (
	"math/big"
	"testing"
)

func testInnerProductProve(t *testing.T, a, b []*big.Int) {
	t.Helper()
	n := len(a)
	EC = NewECPrimeGroupKey(n)

	c := InnerProduct(a, b)
	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)
	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if !InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		t.Errorf("InnerProductVerify failed for n=%d", n)
	}
}

func testInnerProductProveFast(t *testing.T, a, b []*big.Int) {
	t.Helper()
	n := len(a)
	EC = NewECPrimeGroupKey(n)

	c := InnerProduct(a, b)
	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)
	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if !InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		t.Errorf("InnerProductVerifyFast failed for n=%d", n)
	}
}

func TestInnerProductProveLen1(t *testing.T) {
	testInnerProductProve(t,
		[]*big.Int{big.NewInt(2)},
		[]*big.Int{big.NewInt(2)},
	)
}

func TestInnerProductProveLen2(t *testing.T) {
	testInnerProductProve(t,
		[]*big.Int{big.NewInt(2), big.NewInt(3)},
		[]*big.Int{big.NewInt(2), big.NewInt(3)},
	)
}

func TestInnerProductProveLen4(t *testing.T) {
	ones := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	testInnerProductProve(t, ones, ones)
}

func TestInnerProductProveLen8(t *testing.T) {
	a := make([]*big.Int, 8)
	b := make([]*big.Int, 8)
	for i := range a {
		a[i] = big.NewInt(1)
		b[i] = big.NewInt(2)
	}
	testInnerProductProve(t, a, b)
}

func TestInnerProductProveLen64Rand(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	a := RandVector(64)
	b := RandVector(64)
	testInnerProductProve(t, a, b)
}

func TestInnerProductVerifyFastLen1(t *testing.T) {
	testInnerProductProveFast(t,
		[]*big.Int{big.NewInt(2)},
		[]*big.Int{big.NewInt(2)},
	)
}

func TestInnerProductVerifyFastLen2(t *testing.T) {
	testInnerProductProveFast(t,
		[]*big.Int{big.NewInt(2), big.NewInt(3)},
		[]*big.Int{big.NewInt(2), big.NewInt(3)},
	)
}

func TestInnerProductVerifyFastLen4(t *testing.T) {
	ones := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	testInnerProductProveFast(t, ones, ones)
}

func TestInnerProductVerifyFastLen8(t *testing.T) {
	a := make([]*big.Int, 8)
	b := make([]*big.Int, 8)
	for i := range a {
		a[i] = big.NewInt(1)
		b[i] = big.NewInt(2)
	}
	testInnerProductProveFast(t, a, b)
}

func TestInnerProductVerifyFastLen64Rand(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	a := RandVector(64)
	b := RandVector(64)
	testInnerProductProveFast(t, a, b)
}
