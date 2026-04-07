package bp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// InnerProduct computes the inner product <a, b> = Σ aᵢ·bᵢ mod N.
// Both slices must have the same length; a length mismatch panics.
func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		panic(fmt.Sprintf("InnerProduct: length mismatch: len(a)=%d len(b)=%d", len(a), len(b)))
	}

	c := big.NewInt(0)
	for i := range a {
		tmp := new(big.Int).Mul(a[i], b[i])
		c = new(big.Int).Add(c, new(big.Int).Mod(tmp, EC.N))
	}
	return new(big.Int).Mod(c, EC.N)
}

// VectorAdd returns the element-wise sum (v + w) mod N.
// Both slices must have the same length; a length mismatch panics.
func VectorAdd(v []*big.Int, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		panic(fmt.Sprintf("VectorAdd: length mismatch: len(v)=%d len(w)=%d", len(v), len(w)))
	}
	result := make([]*big.Int, len(v))
	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), EC.N)
	}
	return result
}

// VectorHadamard returns the element-wise product (v ∘ w) mod N.
// Both slices must have the same length; a length mismatch panics.
func VectorHadamard(v, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		panic(fmt.Sprintf("VectorHadamard: length mismatch: len(v)=%d len(w)=%d", len(v), len(w)))
	}
	result := make([]*big.Int, len(v))
	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], w[i]), EC.N)
	}
	return result
}

// VectorAddScalar returns a new slice where each element is (vᵢ + s) mod N.
func VectorAddScalar(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))
	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], s), EC.N)
	}
	return result
}

// ScalarVectorMul returns a new slice where each element is (s·vᵢ) mod N.
func ScalarVectorMul(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))
	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], s), EC.N)
	}
	return result
}

// PadLeft left-pads str with the pad character until it reaches length l.
func PadLeft(str, pad string, l int) string {
	for len(str) < l {
		str = pad + str
	}
	return str
}

// STRNot flips every '0' to '1' and every '1' to '0' in a binary string.
func STRNot(str string) string {
	result := ""
	for _, ch := range str {
		if ch == '0' {
			result += "1"
		} else {
			result += "0"
		}
	}
	return result
}

// StrToBigIntArray converts a string of decimal digits to a []*big.Int slice.
func StrToBigIntArray(str string) []*big.Int {
	result := make([]*big.Int, len(str))
	for i := range str {
		t, ok := new(big.Int).SetString(string(str[i]), 10)
		if ok {
			result[i] = t
		}
	}
	return result
}

// reverse returns a new slice that is the reversal of l.
func reverse(l []*big.Int) []*big.Int {
	result := make([]*big.Int, len(l))
	for i := range l {
		result[i] = l[len(l)-i-1]
	}
	return result
}

// PowerVector returns the first l powers of base: [1, base, base², …, base^(l-1)] mod N.
func PowerVector(l int, base *big.Int) []*big.Int {
	result := make([]*big.Int, l)
	for i := 0; i < l; i++ {
		result[i] = new(big.Int).Exp(base, big.NewInt(int64(i)), EC.N)
	}
	return result
}

// RandVector returns a slice of l independently-sampled random scalars in [0, N).
func RandVector(l int) []*big.Int {
	result := make([]*big.Int, l)
	for i := 0; i < l; i++ {
		x, err := rand.Int(rand.Reader, EC.N)
		check(err)
		result[i] = x
	}
	return result
}

// VectorSum returns the sum of all elements in y, reduced mod N.
func VectorSum(y []*big.Int) *big.Int {
	result := big.NewInt(0)
	for _, j := range y {
		result = new(big.Int).Mod(new(big.Int).Add(result, j), EC.N)
	}
	return result
}
