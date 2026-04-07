package bp

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// VecLength is the default bit-width used when initialising the package-level
// EC variable in init(). It equals 64, supporting range proofs for values in
// [0, 2^64).
const VecLength = 64

// CryptoParams bundles all the elliptic-curve parameters required by the
// BulletProofs implementation: the curve itself, generator vectors for the
// inner-product argument, the group order, and the commitment generators G and H.
type CryptoParams struct {
	KC  *btcec.KoblitzCurve // secp256k1 concrete curve
	BPG []ECPoint           // per-bit generator vector G for the inner-product argument
	BPH []ECPoint           // per-bit generator vector H for the inner-product argument
	N   *big.Int            // order of the generator group
	U   ECPoint             // auxiliary generator with unknown discrete log relative to G/H
	V   int                 // length of the generator vectors (= number of bits)
	G   ECPoint             // base generator for value commitments
	H   ECPoint             // blinding generator for value commitments
}

// Zero returns the identity element represented as (0, 0) in this package's
// convention. Note that (0, 0) is not a valid secp256k1 affine point; it is
// used solely as the additive identity for the iterative commitment summations.
func (c CryptoParams) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

// check panics if err is non-nil. It is used exclusively to handle errors from
// crypto/rand.Int, which indicate a failure of the operating-system PRNG — a
// condition that is unrecoverable in a cryptographic context.
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// NewECPrimeGroupKey generates a CryptoParams instance for the secp256k1 curve
// with n-element generator vectors. Generators are derived deterministically
// from the curve's base-point x-coordinate by iterative SHA-256 hashing,
// ensuring that no party knows their discrete logs relative to one another.
//
// n must be a power of two for the inner-product argument to work correctly.
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)
	u := ECPoint{big.NewInt(0), big.NewInt(0)}
	cg := ECPoint{}
	ch := ECPoint{}

	j := 0
	confirmed := 0
	for confirmed < (2*n + 3) {
		s256.Write(new(big.Int).Add(curValue, big.NewInt(int64(j))).Bytes())

		potentialXValue := make([]byte, 33)
		binary.LittleEndian.PutUint32(potentialXValue, 2)
		for i, elem := range s256.Sum(nil) {
			potentialXValue[i+1] = elem
		}

		gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
		if err == nil {
			switch {
			case confirmed == 2*n:
				u = ECPoint{gen2.X, gen2.Y}
			case confirmed == 2*n+1:
				cg = ECPoint{gen2.X, gen2.Y}
			case confirmed == 2*n+2:
				ch = ECPoint{gen2.X, gen2.Y}
			default:
				if confirmed%2 == 0 {
					gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
				} else {
					gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
				}
			}
			confirmed++
		}
		j++
	}

	return CryptoParams{
		KC:  btcec.S256(),
		BPG: gen1Vals,
		BPH: gen2Vals,
		N:   btcec.S256().N,
		U:   u,
		V:   n,
		G:   cg,
		H:   ch,
	}
}

func init() {
	EC = NewECPrimeGroupKey(VecLength)
}
