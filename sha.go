package xmcrypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// HashSha1 sha1加密
// plainText 要加密的明文数据
func HashSha1(plainText string) string {
	// 第一种调用方法
	sha1H := sha1.New()
	_, err := sha1H.Write([]byte(plainText))
	if err != nil {
		panic(err)
	}
	result := fmt.Sprintf("%x", sha1H.Sum(nil))
	// 第二种调用方法
	//result := fmt.Sprintf("%x", sha1.Sum([]byte(plainText))) // 也可以这样写：hex.EncodeToString(sha1.Sum([]byte(plainText))
	return result
}

// HashSha256 sha256加密
// plainText 要加密的明文数据
func HashSha256(plainText string) string {
	sha256H := sha256.New()
	_, err := sha256H.Write([]byte(plainText))
	if err != nil {
		panic(err)
	}
	result := fmt.Sprintf("%x", sha256H.Sum(nil))
	return result
}

// HashSha512 sha512加密
// plainText 要加密的明文数据
func HashSha512(plainText string) string {
	sha512H := sha512.New()
	_, err := sha512H.Write([]byte(plainText))
	if err != nil {
		panic(err)
	}
	result := fmt.Sprintf("%x", sha512H.Sum(nil))
	return result
}
