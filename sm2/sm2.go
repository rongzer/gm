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
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"hash"
	"io"
	"math/big"
)

var (
	aesIV = []byte{0x49, 0x56, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x3c, 0x53, 0x4d, 0x32, 0x3e, 0x20, 0x43, 0x54, 0x52} //"IV for <SM2> CTR"
	uid   = []byte{0x72, 0x6f, 0x6e, 0x67, 0x7a, 0x65, 0x72, 0x40, 0x32, 0x30, 0x32, 0x30, 0x6e, 0x6f, 0x2e, 0x31}
	uLen  = []byte{0x0, 0x80}
)

var one = new(big.Int).SetInt64(1)

type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (*big.Int, error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	n = n.Sub(n, one)

	k.Mod(k, n)
	k.Add(k, one)
	return k, nil
}

// Combine the raw data with user ID, curve parameters and public key
// to generate the signed data used in Sign and Verify
func getZ(msg []byte, pub *ecdsa.PublicKey, h hash.Hash) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key should not be nil")
	}
	c, ok := pub.Curve.(curve)
	if !ok {
		return nil, errors.New("the curve type is not SM2Curve")
	}

	h.Reset()
	h.Write(uLen)
	h.Write(uid)
	h.Write(c.ABytes())
	h.Write(c.Params().B.Bytes())
	h.Write(c.Params().Gx.Bytes())
	h.Write(c.Params().Gy.Bytes())
	h.Write(pub.X.Bytes())
	h.Write(pub.Y.Bytes())
	return append(h.Sum(nil), msg...), nil
}

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out []uint64, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func p256GetScalar(out []uint64, in []byte) {
	n := new(big.Int).SetBytes(in)

	if n.Cmp(sm2Curve.N) >= 0 {
		n.Mod(n, sm2Curve.N)
	}
	fromBig(out, n)
}

func maybeReduceModP(in *big.Int) *big.Int {
	if in.Cmp(sm2Curve.P) < 0 {
		return in
	}
	return new(big.Int).Mod(in, sm2Curve.P)
}

func sm2Inverse(out, in []uint64) {
	var stack [6 * 4]uint64
	p2 := stack[4*0 : 4*0+4]
	p4 := stack[4*1 : 4*1+4]
	p8 := stack[4*2 : 4*2+4]
	p16 := stack[4*3 : 4*3+4]
	p32 := stack[4*4 : 4*4+4]

	sm2Sqr(out, in)
	sm2Mul(p2, out, in)

	sm2Sqr(out, p2)
	sm2Sqr(out, out)
	sm2Mul(p4, out, p2)

	sm2Sqr(out, p4)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(p8, out, p4)

	sm2Sqr(out, p8)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(p16, out, p8)

	sm2Sqr(out, p16)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(p32, out, p16)

	sm2Sqr(out, p16)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)

	sm2Mul(out, out, p8)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)

	sm2Mul(out, out, p4)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p2)

	sm2Sqr(out, out)
	sm2Mul(out, out, in)
	sm2Sqr(out, out)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p32)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p32)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p32)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p32)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p32)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p16)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p8)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p4)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, p2)

	sm2Sqr(out, out)
	sm2Sqr(out, out)
	sm2Mul(out, out, in)
}

func boothW5(in uint) (int, int) {
	var s = ^((in >> 5) - 1)
	var d = (1 << 6) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW7(in uint) (int, int) {
	var s = ^((in >> 7) - 1)
	var d = (1 << 8) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}
