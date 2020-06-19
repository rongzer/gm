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
pkg: github.com/rongzer/gm/sm3
BenchmarkSM3
    BenchmarkSM3: sm3_test.go:57: bench using bytes with 444 length
BenchmarkSM3/sha256
BenchmarkSM3/sha256-8         	  745774	      1517 ns/op	       0 B/op	       0 allocs/op
BenchmarkSM3/rongzer-sm3
BenchmarkSM3/rongzer-sm3-8    	  423534	      2662 ns/op	       0 B/op	       0 allocs/op
BenchmarkSM3/mixbee-sm3
BenchmarkSM3/mixbee-sm3-8     	  196801	      5661 ns/op	       0 B/op	       0 allocs/op
BenchmarkSM3/tjfoc-sm3
BenchmarkSM3/tjfoc-sm3-8      	  212660	      5474 ns/op	     608 B/op	       3 allocs/op
BenchmarkSM3/flyinox-sm3
BenchmarkSM3/flyinox-sm3-8    	  274503	      4279 ns/op	       0 B/op	       0 allocs/op
```

## SM4 symmetric encryption

### Usage

```go
package main

import "github.com/rongzer/gm/sm4"

func main() {
    pwd := []byte("1234567890abcdef")
    c, err := sm4.NewCipher(pwd)
    if err != nil {
        panic(err)
    }
    // 加密
    cipherText := make([]byte, 16)
    c.Encrypt(cipherText, []byte("x0x1x2x3x4x5x6x7"))
    println(cipherText)
    // 解密
    plainText := make([]byte, 16)
    c.Decrypt(plainText, cipherText)
    println(plainText)
}

```

### Performance

- Encrypt
```
goos: darwin
goarch: amd64
pkg: github.com/rongzer/gm/sm4
BenchmarkSM4Encrypt
BenchmarkSM4Encrypt/aes
BenchmarkSM4Encrypt/aes-8         	 3961458	       276 ns/op	     448 B/op	       4 allocs/op
BenchmarkSM4Encrypt/rongzer-sm4
BenchmarkSM4Encrypt/rongzer-sm4-8 	 2549397	       456 ns/op	     128 B/op	       1 allocs/op
BenchmarkSM4Encrypt/mixbee-sm4
BenchmarkSM4Encrypt/mixbee-sm4-8  	 1639929	       737 ns/op	     128 B/op	       1 allocs/op
BenchmarkSM4Encrypt/tjfoc-sm4
BenchmarkSM4Encrypt/tjfoc-sm4-8   	 1650428	       723 ns/op	     240 B/op	       4 allocs/op
```

- Decrypt
```
goos: darwin
goarch: amd64
pkg: github.com/rongzer/gm/sm4
BenchmarkSM4Decrypt
BenchmarkSM4Decrypt/aes
BenchmarkSM4Decrypt/aes-8         	 4316817	       268 ns/op	     448 B/op	       4 allocs/op
BenchmarkSM4Decrypt/rongzer-sm4
BenchmarkSM4Decrypt/rongzer-sm4-8 	 2668842	       444 ns/op	     128 B/op	       1 allocs/op
BenchmarkSM4Decrypt/mixbee-sm4
BenchmarkSM4Decrypt/mixbee-sm4-8  	 1612585	       739 ns/op	     128 B/op	       1 allocs/op
BenchmarkSM4Decrypt/tjfoc-sm4
BenchmarkSM4Decrypt/tjfoc-sm4-8   	 1649646	       731 ns/op	     240 B/op	       4 allocs/op
```
