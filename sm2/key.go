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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

type PrivateKey struct {
	*ecdsa.PrivateKey
}

type sm2Signature struct {
	R, S *big.Int
}

func (p *PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(p, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(sm2Signature{r, s})
}

func GenerateKey() (*PrivateKey, error) {
	d, x, y, err := elliptic.GenerateKey(sm2Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate elliptic key error %w", err)
	}
	return &PrivateKey{
		PrivateKey: &ecdsa.PrivateKey{
			D: new(big.Int).SetBytes(d),
			PublicKey: ecdsa.PublicKey{
				X:     x,
				Y:     y,
				Curve: sm2Curve,
			},
		},
	}, nil
}
