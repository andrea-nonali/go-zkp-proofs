// Package bp implements BulletProofs range proofs on the secp256k1 elliptic curve.
//
// BulletProofs allow a prover to convince a verifier that a committed value lies
// within a given range [0, 2^n) without revealing the value itself. This package
// supports both single-value range proofs (RPProve/RPVerify) and aggregated
// multi-value range proofs (MRPProve/MRPVerify).
//
// The inner product argument (InnerProductProve/InnerProductVerify) is also
// exported as a standalone building block.
//
// Security note: this implementation uses the Fiat-Shamir heuristic to produce
// non-interactive proofs. The hash-to-scalar function uses the decimal string
// representations of curve point coordinates; callers who require provable
// security should switch to a canonical byte encoding.
package bp

import "math/big"

// EC is the package-level CryptoParams used by all proof and verification
// functions. It is initialised in init() with VecLength=64 (suitable for
// 64-bit range proofs). Tests that need a different vector length must
// reinitialise EC before calling proof functions and restore it afterwards.
var EC CryptoParams

// ECPoint represents an affine point on the elliptic curve.
type ECPoint struct {
	X, Y *big.Int
}

// Equal reports whether p and p2 represent the same curve point.
func (p ECPoint) Equal(p2 ECPoint) bool {
	return p.X.Cmp(p2.X) == 0 && p.Y.Cmp(p2.Y) == 0
}

// Mult returns p scaled by scalar s, i.e. s·p.
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, EC.N)
	X, Y := EC.KC.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add returns the curve sum p + p2.
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := EC.KC.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the additive inverse of p on the curve.
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, EC.KC.Params().P)
	return ECPoint{p.X, modValue}
}
