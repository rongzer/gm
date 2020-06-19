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
package sm4

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	// mixbee "github.com/mixbee/mixbee-crypto/sm4"
	// tjfoc "github.com/tjfoc/gmsm/sm4"
)

type sm4Test struct {
	out string
	in  []byte
}

var cases = []sm4Test{
	{"8bb8cf303a703cbf6b2bf9d25717808c", []byte("abcdefghijklmnopqrstuvwxyz")},
	{"d12586cac62af74f4bb48c866faef225", []byte("让人和数据互动得更好")},
	{"27860bbca1a97b37fa97686bcf7f4209", []byte("江苏荣泽信息科技股份有限公司，依托于对区块链和人工智能的人才和技术储备，与政府、高校、金融机构、众多品牌企业一起，把多方资源重新梳理，用区块链和人工智能技术重构业务场景，在构建新一代可信网络的过程中，不断催生交易便捷的可信数字资产，通过技术手段对泛金融的资产进行高效配置，推动新经济的发展与落地。")},
	{"a5dc55ef55df6f2ee42af816a2d370ad", []byte("荣泽科技作为全球首批联盟链技术企业，是区块链在政务应用领域和公众服务领域的先行实践者，在电子政务、普惠金融、智慧医疗、司法公证、政府创新服务、冠字号管理、供应链金融等业务场景均有落地项目。其中公司与南京市政府合作的“基于区块链技术的电子证照平台“成为全球首例，并获得了《国家经济信息系统优秀研究成果一等奖》、《江苏省信息系统优秀研究成果一等奖》以及《2019中国政府信息化产品技术创新奖》。\n\n      目前，荣泽已经助力南京市政府，通过“基于区块链技术的政务数据共享体系”重构了政府部门间的数据共享机制和政务流程再造，实现了政务数据与金融数据的有序共享，并在不断推进政务数据向医疗、公共信用、新零售等公共服务场景延伸。有效消除数据壁垒，使政务数据、金融数据、企业数据、个人数据实现有序流动，从而支撑数据共享平台、数据开放平台、数据服务平台建设，促进全社会的可信数据协同共享。")},
}

var key = []byte("1234567890abcdef")

func TestSm4Encrypt(t *testing.T) {
	c, _ := NewCipher(key)
	out := make([]byte, 16)
	for i := range cases {
		c.Encrypt(out, cases[i].in)
		if cases[i].out != hex.EncodeToString(out[:]) {
			t.Errorf("%s hash not match", cases[i].in)
		}
	}
}

func TestSm4Decrypt(t *testing.T) {
	c, _ := NewCipher(key)
	out := make([]byte, 16)
	for i := range cases {
		in, _ := hex.DecodeString(cases[i].out)
		c.Decrypt(out, in)
		if !bytes.Equal(out[:], cases[i].in[:16]) {
			t.Errorf("%s hash not match", cases[i].in)
		}
	}
}

func BenchmarkSM4Encrypt(b *testing.B) {
	in := cases[3].in
	out := make([]byte, 16)
	b.Run("aes", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, _ := aes.NewCipher(key)
			c.Encrypt(out, in)
		}
	})
	b.Run("rongzer-sm4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, _ := NewCipher(key)
			c.Encrypt(out, in)
		}
	})
	//b.Run("mixbee-sm4", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		c, _ := mixbee.NewCipher(key)
	//		c.Encrypt(out, in)
	//	}
	//})
	//b.Run("tjfoc-sm4", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		c, _ := tjfoc.NewCipher(key)
	//		c.Encrypt(out, in)
	//	}
	//})
}

func BenchmarkSM4Decrypt(b *testing.B) {
	in, _ := hex.DecodeString(cases[3].out)
	out := make([]byte, 16)
	b.Run("aes", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, _ := aes.NewCipher(key)
			c.Decrypt(out, in)
		}
	})
	b.Run("rongzer-sm4", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, _ := NewCipher(key)
			c.Decrypt(out, in)
		}
	})
	//b.Run("mixbee-sm4", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		c, _ := mixbee.NewCipher(key)
	//		c.Decrypt(out, in)
	//	}
	//})
	//b.Run("tjfoc-sm4", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		c, _ := tjfoc.NewCipher(key)
	//		c.Decrypt(out, in)
	//	}
	//})
}
