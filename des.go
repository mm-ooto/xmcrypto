package xmcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// DesCBCEncrypt DES加密（CBC模式）
// plaintext代表明文，secretKey代表密钥（密钥长度必须是8的倍数）
func DesCBCEncrypt(plaintext, secretKey []byte) ([]byte, error) {
	block, err := des.NewCipher(secretKey)
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

// DesCBCDecrypt DES解密（CBC模式）
// ciphertext代表密文，secretKey代表密钥（密钥长度必须是8的倍数）
func DesCBCDecrypt(ciphertext, secretKey []byte) ([]byte, error) {
	block, err := des.NewCipher(secretKey)
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


// DesCFBEncrypt DES加密（CFB模式）
// plaintext代表明文，secretKey代表密钥（密钥长度必须是8的倍数）
func DesCFBEncrypt(plaintext, secretKey []byte) ([]byte, error) {
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

// DesCFBDecrypt DES解密（CFB模式）
// ciphertext代表密文，secretKey代表密钥（密钥长度必须是8的倍数）
func DesCFBDecrypt(ciphertext, secretKey []byte) ([]byte, error) {
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