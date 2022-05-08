package xmcrypto

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Md51 对一个字符串进行MD5加密,不可解密
// 使用Md5对字符串进行加密的几种方式
func Md51(plainText string) string {
	h := md5.New()
	_, err := h.Write([]byte(plainText))
	if err != nil {
		panic(err)
	}
	// EncodeToString(src []byte) string 将数据src编码为字符串s
	md5String := hex.EncodeToString(h.Sum(nil))
	return md5String
}

func Md52(plainText string) string {
	bytes := md5.Sum([]byte(plainText))
	return fmt.Sprintf("%x", bytes)
}

func Md53(plainText string) string {
	h := md5.New()
	_, err := io.WriteString(h, plainText)
	if err != nil {
		panic(err)
	}
	md5String := fmt.Sprintf("%x", h.Sum(nil))
	return md5String
}



// base64加密
// plainText 待加密字符串
func Base64Encode(plainText string) string {
	// 转换成byte类型
	strB := []byte(plainText)
	return base64.StdEncoding.EncodeToString(strB)
}

// base64解密
// plainText 待解密字符串
func Base64Decode(plainText string) string {
	// 转换成byte类型
	bytes, _ := base64.StdEncoding.DecodeString(plainText)
	return string(bytes[:])
}