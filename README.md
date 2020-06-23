# GM SM2/3/4 library based on Golang
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<a href="https://godoc.org/github.com/rongzer/gm"><img alt="GoDoc" src="https://godoc.org/github.com/rongzer/gm?status.svg" /></a>

基于Go语言的国密SM2/SM3/SM4加密算法库

Copyright Jiangsu Rongzer Information Technology Co., Ltd. 2020 All Rights Reserved.

版权所有 江苏荣泽信息科技股份有限公司

## SM2 asymmetric encryption

## Usage

```go
package main

import "github.com/rongzer/gm/sm2"

func main() {
    msg := []byte("test message 123012301230")
    // 创建公私钥
    priKey, _ := sm2.GenerateKey()

    // 签名
    r, s, err := sm2.Sign(priKey, msg)
    if err != nil {
    	panic(err)
    }
    
    // 验签
    if !sm2.Verify(&priKey.PublicKey, msg, r, s) {
    	panic(err)
    }
}
```

### Performance

- Sign

```
goos: darwin
goarch: amd64
pkg: github.com/rongzer/gm/sm2
BenchmarkSM2Sign
BenchmarkSM2Sign/ecdsa
BenchmarkSM2Sign/ecdsa-8         	   35288	     32990 ns/op	    2689 B/op	      32 allocs/op
BenchmarkSM2Sign/rongzer-sm2
BenchmarkSM2Sign/rongzer-sm2-8   	   31092	     37520 ns/op	    4604 B/op	      62 allocs/op
BenchmarkSM2Sign/flyinox-sm2
BenchmarkSM2Sign/flyinox-sm2-8   	     444	   2787993 ns/op	  868626 B/op	    9264 allocs/op
BenchmarkSM2Sign/mixbee-sm2
BenchmarkSM2Sign/mixbee-sm2-8    	   28002	     43236 ns/op	    4722 B/op	      67 allocs/op
BenchmarkSM2Sign/tjfoc-sm2
BenchmarkSM2Sign/tjfoc-sm2-8     	    3193	    362459 ns/op	    5731 B/op	      79 allocs/op
```

- Verify

```
goos: darwin
goarch: amd64
pkg: github.com/rongzer/gm/sm2
BenchmarkSM2Verify
BenchmarkSM2Verify/ecdsa
BenchmarkSM2Verify/ecdsa-8         	   10000	    100811 ns/op	     928 B/op	      16 allocs/op
BenchmarkSM2Verify/rongzer-sm2
BenchmarkSM2Verify/rongzer-sm2-8   	   10000	    111609 ns/op	    3729 B/op	      33 allocs/op
BenchmarkSM2Verify/flyinox-sm2
BenchmarkSM2Verify/flyinox-sm2-8   	     234	   5148109 ns/op	 1773310 B/op	   18892 allocs/op
BenchmarkSM2Verify/mixbee-sm2
BenchmarkSM2Verify/mixbee-sm2-8    	   10000	    119324 ns/op	    3763 B/op	      36 allocs/op
BenchmarkSM2Verify/tjfoc-sm2
BenchmarkSM2Verify/tjfoc-sm2-8     	     590	   2134330 ns/op	   82878 B/op	    1690 allocs/op
```

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
