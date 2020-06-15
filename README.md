# GM SM2/3/4 library based on Golang
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<a href="https://godoc.org/github.com/rongzer/gm"><img alt="GoDoc" src="https://godoc.org/github.com/rongzer/gm?status.svg" /></a>

基于Go语言的国密SM2/SM3/SM4加密算法库

Copyright Jiangsu Rongzer Information Technology Co., Ltd. 2020 All Rights Reserved.

版权所有 江苏荣泽信息科技股份有限公司

## SM2

TODO

## SM3 hash algorithm

## Usage

```go
package main

import "github.com/rongzer/gm/sm3"

func main() {
    // 用法1
    digit := sm3.SumSM3([]byte("test"))
    println(digit)

    // 用法2
    s := sm3.New()
    s.Write([]byte("test"))
    println(s.Sum(nil))
}
```

### Performance
```
goos: darwin
goarch: amd64
pkg: github.com/rblockchain/gm/sm3
BenchmarkSM3: bench using bytes with 444 length
BenchmarkSM3/sha256
BenchmarkSM3/sha256-8         	  735931	      1545 ns/op	       0 B/op	       0 allocs/op
BenchmarkSM3/rongzer-sm3
BenchmarkSM3/rongzer-sm3-8    	  306820	      3741 ns/op	      32 B/op	       1 allocs/op
BenchmarkSM3/mixbee-sm3
BenchmarkSM3/mixbee-sm3-8     	  197480	      5785 ns/op	       0 B/op	       0 allocs/op
BenchmarkSM3/tjfoc-sm3
BenchmarkSM3/tjfoc-sm3-8      	  208290	      5428 ns/op	     608 B/op	       3 allocs/op
BenchmarkSM3/flyinox-sm3
BenchmarkSM3/flyinox-sm3-8    	  275706	      4258 ns/op	       0 B/op	       0 allocs/op
```

## SM4

TODO