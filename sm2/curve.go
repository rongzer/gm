// Copyright Jiangsu Rongzer Information Technology Co., Ltd. 2020 All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//                 http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sm2

import (
	"crypto/elliptic"
	"math/big"
)

var sm2Curve curve

func init() {
	sm2Curve.CurveParams = &elliptic.CurveParams{Name: "sm2p256v1"}
	sm2Curve.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2Curve.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Curve.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2Curve.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Curve.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2Curve.BitSize = 256
	sm2Curve.a = []byte{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC}
}

var rr0 = []uint64{0x0000000200000003, 0x00000002FFFFFFFF, 0x0000000100000001, 0x0000000400000002}

type curve struct {
	*elliptic.CurveParams
	a []byte
}

func (c curve) Params() *elliptic.CurveParams {
	return c.CurveParams
}

func (c curve) ABytes() []byte {
	return c.a
}

func (c curve) Inverse(k *big.Int) *big.Int {
	if k.Sign() < 0 {
		// This should never happen.
		k = new(big.Int).Neg(k)
	}
	if k.Cmp(sm2Curve.N) >= 0 {
		// This should never happen.
		k = new(big.Int).Mod(k, sm2Curve.N)
	}

	// table will store precomputed powers of x. The four words at index
	// 4×i store x^(i+1).
	var table [4 * 15]uint64

	x := make([]uint64, 4)
	fromBig(x[:], k)
	// This code operates in the Montgomery domain where R = 2^256 mod n
	// and n is the order of the scalar field. (See initP256 for the
	// value.) Elements in the Montgomery domain take the form a×R and
	// multiplication of x and y in the calculates (x × y × R^-1) mod n. RR
	// is R×R mod n thus the Montgomery multiplication x and RR gives x×R,
	// i.e. converts x into the Montgomery domain.
	var rr1 = []uint64{0x901192AF7C114F20, 0x3464504ADE6FA2FA, 0x620FC84C3AFFE0D4, 0x1EB5E412A22B3D3B}
	sm2OrdMul(table[:4], x, rr1)

	// Prepare the table, no need in constant time access, because the
	// power is not a secret. (Entry 0 is never used.)
	for i := 2; i < 16; i += 2 {
		sm2OrdSqr(table[4*(i-1):], table[4*((i/2)-1):], 1)
		sm2OrdMul(table[4*i:], table[4*(i-1):], table[:4])
	}

	x[0] = table[4*14+0]
	x[1] = table[4*14+1]
	x[2] = table[4*14+2]
	x[3] = table[4*14+3]

	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[4*14:4*14+4])
	t := make([]uint64, 4, 4)
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2OrdSqr(x, x, 8)
	sm2OrdMul(x, x, t)
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2OrdSqr(x, x, 16)
	sm2OrdMul(x, x, t)
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2OrdSqr(x, x, 64)
	sm2OrdMul(x, x, t)
	sm2OrdSqr(x, x, 32)
	sm2OrdMul(x, x, t)

	// Remaining 32 windows
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[40:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[44:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[52:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[20:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[56:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[36:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[36:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[48:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[36:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[24:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[0:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[24:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[32:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[52:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[28:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[12:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[56:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[8:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[40:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[32:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[44:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[36:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[44:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[4:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[56:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[44:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[20:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[8:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[4:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[16:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[12:])
	sm2OrdSqr(x, x, 4)
	sm2OrdMul(x, x, table[56:])

	// Multiplying by one in the Montgomery domain converts a Montgomery
	// value out of the domain.
	one := []uint64{1, 0, 0, 0}
	sm2OrdMul(x, x, one)

	xOut := make([]byte, 32)
	sm2LittleToBig(xOut, x)
	return new(big.Int).SetBytes(xOut)
}

func (c curve) CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	var r1, r2 point
	p256GetScalar(scalarReversed, baseScalar)
	r1.baseMult(scalarReversed)

	p256GetScalar(scalarReversed, scalar)
	fromBig(r2.xyz[0:4], maybeReduceModP(bigX))
	fromBig(r2.xyz[4:8], maybeReduceModP(bigY))
	sm2Mul(r2.xyz[0:4], r2.xyz[0:4], rr0[:])
	sm2Mul(r2.xyz[4:8], r2.xyz[4:8], rr0[:])

	// This sets r2's Z value to 1, in the Montgomery domain.
	r2.xyz[8] = 0x0000000000000001
	r2.xyz[9] = 0x00000000FFFFFFFF
	r2.xyz[10] = 0x0000000000000000
	r2.xyz[11] = 0x0000000100000000

	r2.scalarMult(scalarReversed)
	sm2PointAddAsm(r1.xyz[:], r1.xyz[:], r2.xyz[:])
	return r1.pointToAffine()
}

func (c curve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	p256GetScalar(scalarReversed, scalar)
	var r point
	r.baseMult(scalarReversed)

	return r.pointToAffine()
}

func (c curve) ScalarMult(bigX, bigY *big.Int, scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	p256GetScalar(scalarReversed, scalar)

	var r point
	fromBig(r.xyz[0:4], maybeReduceModP(bigX))
	fromBig(r.xyz[4:8], maybeReduceModP(bigY))
	sm2Mul(r.xyz[0:4], r.xyz[0:4], rr0[:])
	sm2Mul(r.xyz[4:8], r.xyz[4:8], rr0[:])
	// This sets r2's Z value to 1, in the Montgomery domain.
	r.xyz[8] = 0x0000000000000001
	r.xyz[9] = 0x00000000FFFFFFFF
	r.xyz[10] = 0x0000000000000000
	r.xyz[11] = 0x0000000100000000

	r.scalarMult(scalarReversed)
	return r.pointToAffine()
}
