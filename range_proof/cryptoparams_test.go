package bp

import (
	"math/big"
	"testing"
)

// BenchmarkMRPVerifySize measures proof generation and verification time for
// aggregated multi-range proofs of varying sizes (1, 2, 4, … values).
func BenchmarkMRPVerifySize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 1; j < 257; j *= 2 {
			values := make([]*big.Int, j)
			for k := range values {
				values[k] = big.NewInt(0)
			}

			EC = NewECPrimeGroupKey(64 * len(values))
			proof, err := MRPProve(values)
			if err != nil {
				b.Fatalf("MRPProve failed: %v", err)
			}

			if !MRPVerify(proof) {
				b.Errorf("MRPVerify failed for %d values", j)
			}
		}
	}
}

var benchResult MultiRangeProof
var benchVerify bool

func BenchmarkMRPProve16(b *testing.B) {
	values := make([]*big.Int, 16)
	for k := range values {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))

	var r MultiRangeProof
	for i := 0; i < b.N; i++ {
		var err error
		r, err = MRPProve(values)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchResult = r
}

func BenchmarkMRPVerify16(b *testing.B) {
	values := make([]*big.Int, 16)
	for k := range values {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	proof, err := MRPProve(values)
	if err != nil {
		b.Fatal(err)
	}

	var r bool
	for i := 0; i < b.N; i++ {
		r = MRPVerify(proof)
	}
	benchVerify = r
}

func BenchmarkMRPProve32(b *testing.B) {
	values := make([]*big.Int, 32)
	for k := range values {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))

	var r MultiRangeProof
	for i := 0; i < b.N; i++ {
		var err error
		r, err = MRPProve(values)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchResult = r
}

func BenchmarkMRPVerify32(b *testing.B) {
	values := make([]*big.Int, 32)
	for k := range values {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	proof, err := MRPProve(values)
	if err != nil {
		b.Fatal(err)
	}

	var r bool
	for i := 0; i < b.N; i++ {
		r = MRPVerify(proof)
	}
	benchVerify = r
}
