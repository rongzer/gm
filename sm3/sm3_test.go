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
	"crypto/sha256"
	"encoding/hex"
	"testing"

	// flyinox "github.com/flyinox/crypto/sm/sm3"
	// mixbee "github.com/mixbee/mixbee-crypto/sm3"
	// tjfoc "github.com/tjfoc/gmsm/sm3"
)

type sm3Test struct {
	out string
	in  string
}

var cases = []sm3Test{
	{"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", ""},
	{"623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88", "a"},
	{"e07d8ee6e54586a459e30eb8d809e02194558e2b0b235a31f3226a3687faab88", "ab"},
	{"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"},
	{"82ec580fe6d36ae4f81cae3c73f4a5b3b5a09c943172dc9053c69fd8e18dca1e", "abcd"},
	{"afe4ccac5ab7d52bcae36373676215368baf52d3905e1fecbe369cc120e97628", "abcde"},
	{"5d60e23c9fe29b5e62517e144ad67541c6eb132c8926637b6393fe8d9b62b3bf", "abcdef"},
	{"08b7ee8f741bfb63907fcd0029ae3fd6403e6927b50ed9f04665b22eab81e9b7", "abcdefg"},
	{"1fe46fe782fa5618721cdf61de2e50c0639f4b26f6568f9c67b128f5610ced68", "abcdefgh"},
	{"0654f4e3ee1061cbad10a84879af8de6a1c6be9c6e928110a6400b17da1068db", "abcdefghi"},
	{"a30f4e801d2fdc7f2de4bee4d3f5d892b15f6d474a54f5bc96f01b035aa04345", "abcdefghij"},
	{"c4a7ae1999b7ee1b01af233245d6014f942d149e2ba1ec46768960eb1799d33b", "让人和数据互动得更好"},
	{"85b5a28404b52138d64910f06111fe3c3ec0f887e7e09e4263031e1c2baa9fcd", "江苏荣泽信息科技股份有限公司"},
	{"96f9efe8694edbb855b7f60ede78c505effa33c97c2e5c2dcd334ce9cf2d04d3", "江苏荣泽信息科技股份有限公司，依托于对区块链和人工智能的人才和技术储备，与政府、高校、金融机构、众多品牌企业一起，把多方资源重新梳理，用区块链和人工智能技术重构业务场景，在构建新一代可信网络的过程中，不断催生交易便捷的可信数字资产，通过技术手段对泛金融的资产进行高效配置，推动新经济的发展与落地。"},
	{"be1f37d3200994cb0d5f5481fa4d2b2c123da7b2838a02a64a10c4a9e9280e5f", "荣泽科技作为全球首批联盟链技术企业，是区块链在政务应用领域和公众服务领域的先行实践者，在电子政务、普惠金融、智慧医疗、司法公证、政府创新服务、冠字号管理、供应链金融等业务场景均有落地项目。其中公司与南京市政府合作的“基于区块链技术的电子证照平台“成为全球首例，并获得了《国家经济信息系统优秀研究成果一等奖》、《江苏省信息系统优秀研究成果一等奖》以及《2019中国政府信息化产品技术创新奖》。\n\n      目前，荣泽已经助力南京市政府，通过“基于区块链技术的政务数据共享体系”重构了政府部门间的数据共享机制和政务流程再造，实现了政务数据与金融数据的有序共享，并在不断推进政务数据向医疗、公共信用、新零售等公共服务场景延伸。有效消除数据壁垒，使政务数据、金融数据、企业数据、个人数据实现有序流动，从而支撑数据共享平台、数据开放平台、数据服务平台建设，促进全社会的可信数据协同共享。"},
}

func TestSm3Sum(t *testing.T) {
	for i := range cases {
		d := SumSM3([]byte(cases[i].in))
		if cases[i].out != hex.EncodeToString(d[:]) {
			t.Errorf("%s hash not match", cases[i].in)
		}
	}
}

func BenchmarkSM3(b *testing.B) {
	in := []byte(cases[13].in)
	b.Logf("bench using bytes with %d length", len(in))
	b.Run("sha256", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sha256.Sum256(in)
		}
	})
	b.Run("rongzer-sm3", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			SumSM3(in)
		}
	})
	//b.Run("mixbee-sm3", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		mixbee.Sum(in)
	//	}
	//})
	//b.Run("tjfoc-sm3", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		tjfoc.Sm3Sum(in)
	//	}
	//})
	//b.Run("flyinox-sm3", func(b *testing.B) {
	//	b.ReportAllocs()
	//	b.ResetTimer()
	//	for i := 0; i < b.N; i++ {
	//		flyinox.SumSM3(in)
	//	}
	//})
}
