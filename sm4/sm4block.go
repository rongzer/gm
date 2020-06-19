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

import "math/bits"

// Encrypt one block from src into dst, using the expanded key xk.
func encryptBlockGo(subKeys []uint32, dst, src []byte) {
	m := []uint32{
		(uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | (uint32(src[3])),
		(uint32(src[4]) << 24) | (uint32(src[5]) << 16) | (uint32(src[6]) << 8) | (uint32(src[7])),
		(uint32(src[8]) << 24) | (uint32(src[9]) << 16) | (uint32(src[10]) << 8) | (uint32(src[11])),
		(uint32(src[12]) << 24) | (uint32(src[13]) << 16) | (uint32(src[14]) << 8) | (uint32(src[15])),
	}

	tmp := m[0] ^ f(m[1]^m[2]^m[3]^subKeys[0])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[2])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[3])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[4])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[5])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[6])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[7])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[8])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[9])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[10])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[11])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[12])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[13])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[14])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[15])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[16])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[17])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[18])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[19])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[20])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[21])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[22])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[23])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[24])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[25])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[26])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[27])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[28])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[29])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[30])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[31])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp

	dst[0*4] = uint8(m[3] >> 24)
	dst[0*4+1] = uint8(m[3] >> 16)
	dst[0*4+2] = uint8(m[3] >> 8)
	dst[0*4+3] = uint8(m[3])
	dst[1*4] = uint8(m[2] >> 24)
	dst[1*4+1] = uint8(m[2] >> 16)
	dst[1*4+2] = uint8(m[2] >> 8)
	dst[1*4+3] = uint8(m[2])
	dst[2*4] = uint8(m[1] >> 24)
	dst[2*4+1] = uint8(m[1] >> 16)
	dst[2*4+2] = uint8(m[1] >> 8)
	dst[2*4+3] = uint8(m[1])
	dst[3*4] = uint8(m[0] >> 24)
	dst[3*4+1] = uint8(m[0] >> 16)
	dst[3*4+2] = uint8(m[0] >> 8)
	dst[3*4+3] = uint8(m[0])
}

// Decrypt one block from src into dst, using the expanded key xk.
func decryptBlockGo(subKeys []uint32, dst, src []byte) {
	m := []uint32{
		(uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | (uint32(src[3])),
		(uint32(src[4]) << 24) | (uint32(src[5]) << 16) | (uint32(src[6]) << 8) | (uint32(src[7])),
		(uint32(src[8]) << 24) | (uint32(src[9]) << 16) | (uint32(src[10]) << 8) | (uint32(src[11])),
		(uint32(src[12]) << 24) | (uint32(src[13]) << 16) | (uint32(src[14]) << 8) | (uint32(src[15])),
	}

	tmp := m[0] ^ f(m[1]^m[2]^m[3]^subKeys[32-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[31-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[30-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[29-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[28-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[27-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[26-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[25-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[24-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[23-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[22-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[21-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[20-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[19-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[18-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[17-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[16-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[15-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[14-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[13-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[12-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[11-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[10-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[9-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[8-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[7-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[6-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[5-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[4-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[3-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[2-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp
	tmp = m[0] ^ f(m[1]^m[2]^m[3]^subKeys[1-1])
	m[0] = m[1]
	m[1] = m[2]
	m[2] = m[3]
	m[3] = tmp

	dst[0*4] = uint8(m[3] >> 24)
	dst[0*4+1] = uint8(m[3] >> 16)
	dst[0*4+2] = uint8(m[3] >> 8)
	dst[0*4+3] = uint8(m[3])
	dst[1*4] = uint8(m[2] >> 24)
	dst[1*4+1] = uint8(m[2] >> 16)
	dst[1*4+2] = uint8(m[2] >> 8)
	dst[1*4+3] = uint8(m[2])
	dst[2*4] = uint8(m[1] >> 24)
	dst[2*4+1] = uint8(m[1] >> 16)
	dst[2*4+2] = uint8(m[1] >> 8)
	dst[2*4+3] = uint8(m[1])
	dst[3*4] = uint8(m[0] >> 24)
	dst[3*4+1] = uint8(m[0] >> 16)
	dst[3*4+2] = uint8(m[0] >> 8)
	dst[3*4+3] = uint8(m[0])
}

func f(x uint32) uint32 {
	b := sBox[uint8(x)] | (sBox[uint8(x>>8)] << 8) | (sBox[uint8(x>>16)] << 16) | (sBox[uint8(x>>24)] << 24)
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^ bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

var sBox = [256]uint32{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}
