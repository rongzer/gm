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

import "math/big"

var sm2Precomputed *[37][64 * 8]uint64

func init() {
	sm2Precomputed = new([37][64 * 8]uint64)

	basePoint := []uint64{
		0x61328990F418029E, 0x3E7981EDDCA6C050, 0xD6A1ED99AC24C3C3, 0x91167A5EE1C13B05,
		0xC1354E593C2D0DDD, 0xC1F5E5788D3295FA, 0x8D4CFB066E2A48F8, 0x63CD65D481D735BD,
		0x0000000000000001, 0x00000000FFFFFFFF, 0x0000000000000000, 0x0000000100000000,
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
				sm2PointDoubleAsm(t1, t1)
			}

			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			sm2Inverse(zInv, t1[8:12])

			sm2Sqr(zInvSq, zInv)
			sm2Mul(zInv, zInv, zInvSq)

			sm2Mul(t1[:4], t1[:4], zInvSq)
			sm2Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(sm2Precomputed[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2PointDoubleAsm(t2, basePoint)
		} else {
			sm2PointAddAsm(t2, t2, basePoint)
		}
	}
}

type point struct {
	xyz [12]uint64
}

func (p *point) pointToAffine() (x, y *big.Int) {
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	sm2Inverse(zInv, p.xyz[8:12])
	sm2Sqr(zInvSq, zInv)
	sm2Mul(zInv, zInv, zInvSq)

	sm2Mul(zInvSq, p.xyz[0:4], zInvSq)
	sm2Mul(zInv, p.xyz[4:8], zInv)

	sm2FromMont(zInvSq, zInvSq)
	sm2FromMont(zInv, zInv)

	xOut := make([]byte, 32)
	yOut := make([]byte, 32)
	sm2LittleToBig(xOut, zInvSq)
	sm2LittleToBig(yOut, zInv)

	return new(big.Int).SetBytes(xOut), new(big.Int).SetBytes(yOut)
}

func (p *point) p256StorePoint(r *[16 * 4 * 3]uint64, index int) {
	copy(r[index*12:], p.xyz[:])
}

func (p *point) baseMult(scalar []uint64) {
	wValue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wValue))
	sm2SelectBase(p.xyz[0:8], sm2Precomputed[0][0:], sel)
	sm2NegCond(p.xyz[4:8], sign)

	// (This is one, in the Montgomery domain.)
	p.xyz[8] = 0x0000000000000001
	p.xyz[9] = 0x00000000FFFFFFFF
	p.xyz[10] = 0x0000000000000000
	p.xyz[11] = 0x0000000100000000

	var t0 point
	// (This is one, in the Montgomery domain.)
	t0.xyz[8] = 0x0000000000000001
	t0.xyz[9] = 0x00000000FFFFFFFF
	t0.xyz[10] = 0x0000000000000000
	t0.xyz[11] = 0x0000000100000000

	index := uint(6)
	zero := sel

	for i := 1; i < 37; i++ {
		v1 := index / 64
		v2 := index % 64
		if index < 192 {
			wValue = ((scalar[v1] >> v2) + (scalar[v1+1] << (64 - v2))) & 0xff
		} else {
			wValue = (scalar[v1] >> v2) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wValue))
		sm2SelectBase(t0.xyz[0:8], sm2Precomputed[i][0:], sel)
		sm2PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0.xyz[0:8], sign, sel, zero)
		zero |= sel
	}
}

func (p *point) scalarMult(scalar []uint64) {
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var precomp [16 * 4 * 3]uint64
	var t0, t1, t2, t3 point

	// Prepare the table
	p.p256StorePoint(&precomp, 0)

	sm2PointDoubleAsm(t0.xyz[:], p.xyz[:])
	sm2PointDoubleAsm(t1.xyz[:], t0.xyz[:])
	sm2PointDoubleAsm(t2.xyz[:], t1.xyz[:])
	sm2PointDoubleAsm(t3.xyz[:], t2.xyz[:])
	t0.p256StorePoint(&precomp, 1)
	t1.p256StorePoint(&precomp, 3)
	t2.p256StorePoint(&precomp, 7)
	t3.p256StorePoint(&precomp, 15)

	sm2PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	sm2PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	sm2PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])
	t0.p256StorePoint(&precomp, 2)
	t1.p256StorePoint(&precomp, 4)
	t2.p256StorePoint(&precomp, 8)

	sm2PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	sm2PointDoubleAsm(t1.xyz[:], t1.xyz[:])
	t0.p256StorePoint(&precomp, 5)
	t1.p256StorePoint(&precomp, 9)

	sm2PointAddAsm(t2.xyz[:], t0.xyz[:], p.xyz[:])
	sm2PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	t2.p256StorePoint(&precomp, 6)
	t1.p256StorePoint(&precomp, 10)

	sm2PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	sm2PointDoubleAsm(t2.xyz[:], t2.xyz[:])
	t0.p256StorePoint(&precomp, 11)
	t2.p256StorePoint(&precomp, 13)

	sm2PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	sm2PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])
	t0.p256StorePoint(&precomp, 12)
	t2.p256StorePoint(&precomp, 14)

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wValue := (scalar[index/64] >> (index % 64)) & 0x3f
	sel, _ = boothW5(uint(wValue))

	sm2Select(p.xyz[0:12], precomp[0:], sel)
	zero := sel

	for index > 4 {
		index -= 5
		sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2PointDoubleAsm(p.xyz[:], p.xyz[:])

		v1 := index / 64
		v2 := index % 64
		if index < 192 {
			wValue = ((scalar[v1] >> v2) + (scalar[v1+1] << (64 - v2))) & 0x3f
		} else {
			wValue = (scalar[v1] >> v2) & 0x3f
		}

		sel, sign = boothW5(uint(wValue))

		sm2Select(t0.xyz[0:], precomp[0:], sel)
		sm2NegCond(t0.xyz[4:8], sign)
		sm2PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
		sm2MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
		sm2MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
		zero |= sel
	}

	sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2PointDoubleAsm(p.xyz[:], p.xyz[:])

	wValue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wValue))

	sm2Select(t0.xyz[0:], precomp[0:], sel)
	sm2NegCond(t0.xyz[4:8], sign)
	sm2PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
	sm2MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
	sm2MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
}
