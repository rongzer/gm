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

// Functions implemented in asm_amd64.s
// Montgomery multiplication modulo P256
func sm2Mul(res, in1, in2 []uint64)

// Montgomery square modulo P256
func sm2Sqr(res, in []uint64)

// Montgomery multiplication by 1
func sm2FromMont(res, in []uint64)

// iff cond == 1  val <- -val
func sm2NegCond(val []uint64, cond int)

// if cond == 0 res <- b; else res <- a
func sm2MovCond(res, a, b []uint64, cond int)

// Endianness swap
func sm2BigToLittle(res []uint64, in []byte)
func sm2LittleToBig(res []byte, in []uint64)

// Constant time table access
func sm2Select(point, table []uint64, idx int)
func sm2SelectBase(point, table []uint64, idx int)

// Montgomery multiplication modulo Ord(G)
func sm2OrdMul(res, in1, in2 []uint64)

// Montgomery square modulo Ord(G), repeated n times
func sm2OrdSqr(res, in []uint64, n int)

// Point add with in2 being affine point
// If sign == 1 -> in2 = -in2
// If sel == 0 -> res = in1
// if zero == 0 -> res = in2
func sm2PointAddAffineAsm(res, in1, in2 []uint64, sign, sel, zero int)

// Point add
func sm2PointAddAsm(res, in1, in2 []uint64)

// Point double
func sm2PointDoubleAsm(res, in []uint64)
