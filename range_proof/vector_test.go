package bp

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestValueBreakdown(t *testing.T) {
	v := big.NewInt(20)
	bits := reverse(StrToBigIntArray(PadLeft(format(v), "0", 64)))
	powers := PowerVector(64, big.NewInt(2))
	calc := InnerProduct(bits, powers)
	if v.Cmp(calc) != 0 {
		t.Errorf("binary breakdown of %s reconstructed to %s", v, calc)
	}
}

func TestValueBreakdownRandom(t *testing.T) {
	v, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)
	bits := reverse(StrToBigIntArray(PadLeft(format(v), "0", 64)))
	powers := PowerVector(64, big.NewInt(2))
	calc := InnerProduct(bits, powers)
	if v.Cmp(calc) != 0 {
		t.Errorf("binary breakdown of random value %s reconstructed to %s", v, calc)
	}
}

func TestVectorHadamardIdentity(t *testing.T) {
	a := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	c := VectorHadamard(a, a)
	for i := range c {
		if c[i].Cmp(a[i]) != 0 {
			t.Errorf("VectorHadamard(1,...,1) ∘ (1,...,1): element %d is %s, want 1", i, c[i])
		}
	}
}

func TestInnerProduct(t *testing.T) {
	a := []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2), big.NewInt(2)}
	b := []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2), big.NewInt(2)}
	c := InnerProduct(a, b)
	if c.Cmp(big.NewInt(16)) != 0 {
		t.Errorf("InnerProduct([2,2,2,2],[2,2,2,2]) = %s, want 16", c)
	}
}

// format wraps fmt.Sprintf to avoid importing fmt in tests.
func format(v *big.Int) string {
	return v.Text(2)
}
