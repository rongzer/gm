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
	"crypto/rand"
	"io"
	"testing"
	//flyinox "github.com/flyinox/crypto/sm/sm2"
	//mixbee_keypair "github.com/mixbee/mixbee-crypto/keypair"
	//mixbee_signature "github.com/mixbee/mixbee-crypto/signature"
	//tjfoc "github.com/tjfoc/gmsm/sm2"
)

func TestSignAndVerify(t *testing.T) {
	msg := []byte("test message 123012301230")

	priKey, _ := GenerateKey()
	r, s, err := Sign(priKey, msg)
	if err != nil {
		t.Fatalf("signing error: %s", err)
	}

	if !Verify(&priKey.PublicKey, msg, r, s) {
		t.Error("verification failed")
	}
}

func BenchmarkSM2Sign(b *testing.B) {
	msg := make([]byte, 256)
	_, _ = io.ReadFull(rand.Reader, msg[:])

	b.Run("ecdsa", func(b *testing.B) {
		priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ecdsa.Sign(rand.Reader, priKey, msg)
		}
	})

	b.Run("rongzer-sm2", func(b *testing.B) {
		priKey, _ := GenerateKey()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			Sign(priKey, msg)
		}
	})

	//b.Run("flyinox-sm2", func(b *testing.B) {
	//	priKey, _ := flyinox.GenerateKey(rand.Reader)
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		flyinox.Sign(rand.Reader, priKey, msg)
	//	}
	//})
	//
	//b.Run("mixbee-sm2", func(b *testing.B) {
	//	pri, _, _ := mixbee_keypair.GenerateKeyPair(mixbee_keypair.PK_SM2, mixbee_keypair.SM2P256V1)
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		mixbee_signature.Sign(mixbee_signature.SM3withSM2, pri, msg, nil)
	//	}
	//})
	//
	//b.Run("tjfoc-sm2", func(b *testing.B) {
	//	priKey, _ := tjfoc.GenerateKey()
	//
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		tjfoc.Sign(priKey, msg)
	//	}
	//})
}

func BenchmarkSM2Verify(b *testing.B) {
	msg := make([]byte, 256)
	_, _ = io.ReadFull(rand.Reader, msg[:])

	b.Run("ecdsa", func(b *testing.B) {
		priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		r, s, _ := ecdsa.Sign(rand.Reader, priKey, msg)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ecdsa.Verify(&priKey.PublicKey, msg, r, s)
		}
	})

	b.Run("rongzer-sm2", func(b *testing.B) {
		priKey, _ := GenerateKey()
		r, s, _ := Sign(priKey, msg)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			Verify(&priKey.PublicKey, msg, r, s)
		}
	})

	//b.Run("flyinox-sm2", func(b *testing.B) {
	//	priKey, _ := flyinox.GenerateKey(rand.Reader)
	//	r, s, _ := flyinox.Sign(rand.Reader, priKey, msg)
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		flyinox.Verify(&priKey.PublicKey, msg, r, s)
	//	}
	//})
	//
	//b.Run("mixbee-sm2", func(b *testing.B) {
	//	pri, _, _ := mixbee_keypair.GenerateKeyPair(mixbee_keypair.PK_SM2, mixbee_keypair.SM2P256V1)
	//	sig, _ := mixbee_signature.Sign(mixbee_signature.SM3withSM2, pri, msg, nil)
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		mixbee_signature.Verify(pri.Public(), msg, sig)
	//	}
	//})
	//
	//b.Run("tjfoc-sm2", func(b *testing.B) {
	//	priKey, _ := tjfoc.GenerateKey()
	//	r, s, _ := tjfoc.Sign(priKey, msg)
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		tjfoc.Verify(&priKey.PublicKey, msg, r, s)
	//	}
	//})
}
