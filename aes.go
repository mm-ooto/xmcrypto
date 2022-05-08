package xmcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// AES是非对称加密算法

// 在采用AES、DES等块加密时，有时需要对不满足一个整块（block）的部分需要进行填充
// 常用的填充的方式就包括ZeroPadding、PKCS5Padding与PKCS7Padding

// 假设每个区块大小为blockSize
// 需要填充的字节长度 = (blockSize - (数据长度 % blockSize))
// 举例如下：
// 情况1：
//    假定块长度为8，数据长度为3，则填充字节数等于5
//    原数据为： FF FF FF
//    填充结果： FF FF FF 05 05 05 05 05
// 情况2：
//    假定块长度为8，数据长度为9，则填充字节数等于7
//    原数据为：FF FF FF FF FF FF FF FF FF
//    填充结果：FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07
// 情况3：
//    假定块长度为8，数据长度为8，则填充字节数等于8
//    原数据为：FF FF FF FF FF FF FF FF
//    填充结果：FF FF FF FF FF FF FF FF 08 08 08 08 08 08 08 08

// PKCS7Padding PKCS7填充：
// <1>已对齐，填充一个长度为blockSize且每个字节均为blockSize的数据。
// <2>未对齐，需要补充的字节个数为n，则填充一个长度为n且每个字节均为n的数据。
func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// PKSC5Padding PKCS5填充：是限制块大小（块大小固定为8字节）的PKCS7Padding
func PKSC5Padding(cipherText []byte) []byte {
	return PKCS7Padding(cipherText, 8)
}

// PKCS7UnPadding 移除填充的字符串
// 在解密后，需要将填充的字符去掉，取最后一位即知道存在多少个补充位
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1]) // 最后一个数据，同时也是填充物的个数
	return origData[:(length - unPadding)]
}

// AesCBCEncrypt AES加密（CBC模式）
// plaintext代表明文，secretKey代表密钥（密钥长度必须是16的倍数）
func AesCBCEncrypt(plaintext, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, secretKey[:blockSize])
	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// AesCBCDecrypt AES解密（CBC模式）
// ciphertext代表密文，secretKey代表密钥（密钥长度必须是16的倍数）
func AesCBCDecrypt(ciphertext, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, secretKey[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

// AesCFBEncrypt AES加密（CFB模式）
// plaintext代表明文，secretKey代表密钥（密钥长度必须是16的倍数）
func AesCFBEncrypt(plaintext, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	stream := cipher.NewCFBEncrypter(block, secretKey[:blockSize])
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// AesCFBDecrypt AES解密（CFB模式）
// ciphertext代表密文，secretKey代表密钥（密钥长度必须是16的倍数）
func AesCFBDecrypt(ciphertext, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	stream := cipher.NewCFBDecrypter(block, secretKey[:blockSize])
	origData := make([]byte, len(ciphertext))
	stream.XORKeyStream(origData, ciphertext)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}
