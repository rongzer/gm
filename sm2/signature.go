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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"

	"github.com/rongzer/gm/sm3"
)

// Sign generates signature for the input message using the private key and id.
// It returns (r, s) as the signature or error.
func Sign(p *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	h := sm3.New()
	mz, err := getZ(msg, &p.PublicKey, h)
	if err != nil {
		return
	}
	h.Reset()
	h.Write(mz)
	digest := h.Sum(nil)

	entropyLen := (p.Params().BitSize + 7) >> 4
	if entropyLen > 32 {
		entropyLen = 32
	}

	entropy := make([]byte, entropyLen)
	_, err = io.ReadFull(rand.Reader, entropy)
	if err != nil {
		return
	}

	priKey := p.D.Bytes()

	md := sha512.New()
	md.Write(priKey)
	md.Write(entropy)
	md.Write(digest[:])

	block, err := aes.NewCipher(md.Sum(nil)[:32])
	if err != nil {
		return
	}

	cspRng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, aesIV),
	}

	N := p.Params().N
	if N.Sign() == 0 {
		err = errors.New("zero parameter")
		return
	}
	var k *big.Int
	e := new(big.Int).SetBytes(digest[:])
	for {
		for {
			k, err = randFieldElement(p.Curve, cspRng)
			if err != nil {
				r = nil
				return
			}

			r, _ = p.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
			if t := new(big.Int).Add(r, k); t.Cmp(N) == 0 {
				break
			}
		}
		D := new(big.Int).SetBytes(priKey)
		rD := new(big.Int).Mul(D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// Verify checks whether the input (r, s) is a valid signature for the message.
func Verify(pub *ecdsa.PublicKey, msg []byte, r, s *big.Int) bool {
	N := pub.Params().N
	if N.Sign() == 0 {
		return false
	}

	t := new(big.Int).Add(r, s)
	t.Mod(t, N)

	var x *big.Int
	if opt, ok := pub.Curve.(combinedMult); ok {
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x1, y1 := pub.ScalarBaseMult(s.Bytes())
		x2, y2 := pub.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = pub.Add(x1, y1, x2, y2)
	}

	h := sm3.New()
	mz, err := getZ(msg, pub, h)
	if err != nil {
		return false
	}

	h.Reset()
	h.Write(mz)
	x.Add(x, new(big.Int).SetBytes(h.Sum(nil)[:]))
	x.Mod(x, N)
	return x.Cmp(r) == 0
}
