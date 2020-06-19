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
	"crypto/cipher"
	"math/bits"
	"strconv"
)

// The AES block size in bytes.
const BlockSize = 16

// A cipher is an instance of SM4 encryption using a particular key.
type sm4Cipher struct {
	subKeys [32]uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "SM4: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the SM4 key, length must be 16.
func NewCipher(key []byte) (cipher.Block, error) {
	if l := len(key); l != BlockSize {
		return nil, KeySizeError(l)
	}
	c := new(sm4Cipher)
	c.generateSubKeys(key)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	encryptBlockGo(c.subKeys[:], dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	decryptBlockGo(c.subKeys[:], dst, src)
}

func (c *sm4Cipher) generateSubKeys(key []byte) {
	k := []uint32{
		(uint32(key[0]) << 24) | (uint32(key[1]) << 16) | (uint32(key[2]) << 8) | (uint32(key[3])) ^ 0xa3b1bac6,
		(uint32(key[4]) << 24) | (uint32(key[5]) << 16) | (uint32(key[6]) << 8) | (uint32(key[7])) ^ 0x56aa3350,
		(uint32(key[8]) << 24) | (uint32(key[9]) << 16) | (uint32(key[10]) << 8) | (uint32(key[11])) ^ 0x677d9197,
		(uint32(key[12]) << 24) | (uint32(key[13]) << 16) | (uint32(key[14]) << 8) | (uint32(key[15])) ^ 0xb27022dc,
	}

	x := k[1] ^ k[2] ^ k[3] ^ 462357
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[0] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[0]
	x = k[1] ^ k[2] ^ k[3] ^ 472066609
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[1] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[1]
	x = k[1] ^ k[2] ^ k[3] ^ 943670861
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[2] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[2]
	x = k[1] ^ k[2] ^ k[3] ^ 1415275113
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[3] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[3]
	x = k[1] ^ k[2] ^ k[3] ^ 1886879365
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[4] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[4]
	x = k[1] ^ k[2] ^ k[3] ^ 2358483617
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[5] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[5]
	x = k[1] ^ k[2] ^ k[3] ^ 2830087869
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[6] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[6]
	x = k[1] ^ k[2] ^ k[3] ^ 3301692121
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[7] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[7]
	x = k[1] ^ k[2] ^ k[3] ^ 3773296373
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[8] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[8]
	x = k[1] ^ k[2] ^ k[3] ^ 4228057617
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[9] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[9]
	x = k[1] ^ k[2] ^ k[3] ^ 404694573
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[10] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[10]
	x = k[1] ^ k[2] ^ k[3] ^ 876298825
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[11] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[11]
	x = k[1] ^ k[2] ^ k[3] ^ 1347903077
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[12] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[12]
	x = k[1] ^ k[2] ^ k[3] ^ 1819507329
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[13] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[13]
	x = k[1] ^ k[2] ^ k[3] ^ 2291111581
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[14] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[14]
	x = k[1] ^ k[2] ^ k[3] ^ 2762715833
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[15] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[15]
	x = k[1] ^ k[2] ^ k[3] ^ 3234320085
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[16] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[16]
	x = k[1] ^ k[2] ^ k[3] ^ 3705924337
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[17] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[17]
	x = k[1] ^ k[2] ^ k[3] ^ 4177462797
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[18] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[18]
	x = k[1] ^ k[2] ^ k[3] ^ 337322537
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[19] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[19]
	x = k[1] ^ k[2] ^ k[3] ^ 808926789
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[20] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[20]
	x = k[1] ^ k[2] ^ k[3] ^ 1280531041
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[21] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[21]
	x = k[1] ^ k[2] ^ k[3] ^ 1752135293
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[22] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[22]
	x = k[1] ^ k[2] ^ k[3] ^ 2223739545
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[23] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[23]
	x = k[1] ^ k[2] ^ k[3] ^ 2695343797
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[24] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[24]
	x = k[1] ^ k[2] ^ k[3] ^ 3166948049
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[25] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[25]
	x = k[1] ^ k[2] ^ k[3] ^ 3638552301
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[26] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[26]
	x = k[1] ^ k[2] ^ k[3] ^ 4110090761
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[27] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[27]
	x = k[1] ^ k[2] ^ k[3] ^ 269950501
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[28] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[28]
	x = k[1] ^ k[2] ^ k[3] ^ 741554753
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[29] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[29]
	x = k[1] ^ k[2] ^ k[3] ^ 1213159005
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[30] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[30]
	x = k[1] ^ k[2] ^ k[3] ^ 1684763257
	x = sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	x = x ^ bits.RotateLeft32(x, 13) ^ bits.RotateLeft32(x, 23)
	c.subKeys[31] = k[0] ^ x
	k[0] = k[1]
	k[1] = k[2]
	k[2] = k[3]
	k[3] = c.subKeys[31]
}
