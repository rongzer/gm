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
package sm3

import (
	"math/bits"
)

var _K = []uint32{
	0x79cc4519,
	0xf3988a32,
	0xe7311465,
	0xce6228cb,
	0x9cc45197,
	0x3988a32f,
	0x7311465e,
	0xe6228cbc,
	0xcc451979,
	0x988a32f3,
	0x311465e7,
	0x6228cbce,
	0xc451979c,
	0x88a32f39,
	0x11465e73,
	0x228cbce6,
	0x9d8a7a87,
	0x3b14f50f,
	0x7629ea1e,
	0xec53d43c,
	0xd8a7a879,
	0xb14f50f3,
	0x629ea1e7,
	0xc53d43ce,
	0x8a7a879d,
	0x14f50f3b,
	0x29ea1e76,
	0x53d43cec,
	0xa7a879d8,
	0x4f50f3b1,
	0x9ea1e762,
	0x3d43cec5,
	0x7a879d8a,
	0xf50f3b14,
	0xea1e7629,
	0xd43cec53,
	0xa879d8a7,
	0x50f3b14f,
	0xa1e7629e,
	0x43cec53d,
	0x879d8a7a,
	0x0f3b14f5,
	0x1e7629ea,
	0x3cec53d4,
	0x79d8a7a8,
	0xf3b14f50,
	0xe7629ea1,
	0xcec53d43,
	0x9d8a7a87,
	0x3b14f50f,
	0x7629ea1e,
	0xec53d43c,
	0xd8a7a879,
	0xb14f50f3,
	0x629ea1e7,
	0xc53d43ce,
	0x8a7a879d,
	0x14f50f3b,
	0x29ea1e76,
	0x53d43cec,
	0xa7a879d8,
	0x4f50f3b1,
	0x9ea1e762,
	0x3d43cec5,
}

func blockGeneric(p []byte, digest [8]uint32) (_digest [8]uint32) {
	var w [68]uint32
	a, b, c, d, e, f, g, h := digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
	for len(p) >= 64 {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		for i := 16; i < 68; i++ {
			v1 := w[i-16] ^ w[i-9] ^ bits.RotateLeft32(w[i-3], 15)
			t1 := v1 ^ bits.RotateLeft32(v1, 15) ^ bits.RotateLeft32(v1, 23)
			w[i] = t1 ^ bits.RotateLeft32(w[i-13], 7) ^ w[i-6]
		}

		A, B, C, D, E, F, G, H := a, b, c, d, e, f, g, h

		for i := 0; i < 16; i++ {
			s1 := bits.RotateLeft32(bits.RotateLeft32(A, 12)+E+_K[i], 7)
			s2 := s1 ^ bits.RotateLeft32(A, 12)
			t1 := (A ^ B ^ C) + D + s2 + (w[i] ^ w[i+4])
			t2 := (E ^ F ^ G) + H + s1 + w[i]
			D = C
			C = bits.RotateLeft32(B, 9)
			B = A
			A = t1
			H = G
			G = bits.RotateLeft32(F, 19)
			F = E
			E = t2 ^ bits.RotateLeft32(t2, 9) ^ bits.RotateLeft32(t2, 17)
		}

		for i := 16; i < 64; i++ {
			s1 := bits.RotateLeft32(bits.RotateLeft32(A, 12)+E+_K[i], 7)
			s2 := s1 ^ bits.RotateLeft32(A, 12)
			t1 := ((A & B) | (A & C) | (B & C)) + D + s2 + (w[i] ^ w[i+4])
			t2 := ((E & F) | (^E & G)) + H + s1 + w[i]
			D = C
			C = bits.RotateLeft32(B, 9)
			B = A
			A = t1
			H = G
			G = bits.RotateLeft32(F, 19)
			F = E
			E = t2 ^ bits.RotateLeft32(t2, 9) ^ bits.RotateLeft32(t2, 17)
		}

		a ^= A
		b ^= B
		c ^= C
		d ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H
		p = p[64:]
	}
	_digest[0], _digest[1], _digest[2], _digest[3], _digest[4], _digest[5], _digest[6], _digest[7] = a, b, c, d, e, f, g, h
	return _digest
}
