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
	"encoding/binary"
	"hash"
)

// The Size of a SM3 checksum in bytes.
const Size = 32

// The block size of SM3 in bytes.
const BlockSize = 64

const (
	init0 = 0x7380166f
	init1 = 0x4914b2b9
	init2 = 0x172442d7
	init3 = 0xda8a0600
	init4 = 0xa96f30bc
	init5 = 0x163138aa
	init6 = 0xe38dee4d
	init7 = 0xb0fb0e4e
)

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// SumSM3 returns the SM3 checksum of the data.
func SumSM3(data []byte) [32]byte {
	var d digest
	d.Reset()
	_, _ = d.Write(data)
	return d.checkSum()
}

type digest struct {
	h   [8]uint32
	x   [64]byte
	nx  int
	len uint64
}

func (d *digest) checkSum() [Size]byte {
	n := d.nx

	var k [64]byte
	copy(k[:], d.x[:n])

	k[n] = 0x80
	if n >= 56 {
		blockGeneric(d, k[:])
		for i := 0; i < 64; i++ {
			k[i] = 0
		}
	}
	binary.BigEndian.PutUint64(k[56:64], d.len<<3)
	blockGeneric(d, k[:])

	var digest [Size]byte

	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(digest[i*4:i*4+4], d.h[i])
	}
	return digest
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Size() int { return Size }

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

// Write hash.Hash interface.
func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum hash.Hash interface.
func (d *digest) Sum(in []byte) []byte {
	_d := *d
	h := _d.checkSum()
	return append(in, h[:]...)
}
