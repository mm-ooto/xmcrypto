package xmcrypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestMD5AndBase64(t *testing.T) {
	t.Log(Md51("TestMD5AndBase64"))
	t.Log(Md52("TestMD5AndBase64"))
	t.Log(Md53("TestMD5AndBase64"))
	res := Base64Encode("TestMD5AndBase64")
	t.Logf("Base64Encode result=%s\n", res)
	t.Logf("Base64Decode result=%s\n", Base64Decode(res))

}

func TestHash(t *testing.T) {
	t.Log(HashSha1("123"))
	t.Log(HashSha256("123"))
	t.Log(HashSha512("123"))
}

func TestAesEncryptAndDecrypt(t *testing.T) {
	secretKey := []byte("#HvL%$o0oNNoOZnk#o2qbqCeQB1iXeIR")
	plaintext := "TestAesEncryptAndDecrypt"
	t.Logf("明文: %s\n秘钥: %s\n", plaintext, string(secretKey))
	ciphertext, err := AesCBCEncrypt([]byte(plaintext), secretKey)
	if err != nil {
		panic(err)
	}
	t.Logf("加密后: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	origin, err := AesCBCDecrypt(ciphertext, secretKey)
	if err != nil {
		panic(err)
	}
	t.Logf("解密后明文: %s\n", string(origin))
}

func TestDesEncryptAndDecrypt(t *testing.T) {
	secretKey := []byte("1234567812345678")
	plaintext := "TestDesEncryptAndDecrypt"

	ciphertext, err := DesCBCEncrypt([]byte(plaintext), secretKey)
	if err != nil {
		panic(err)
	}
	t.Logf("加密后: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	origin, err := DesCBCDecrypt(ciphertext, secretKey)
	if err != nil {
		panic(err)
	}
	t.Logf("解密后明文: %s\n", string(origin))
}

func TestGenerateRSAKey(t *testing.T) {
	GenerateRSAKey(2048)
	//privateKeyByte,publicKeyByte,err:=GenRSAKeyWithPKCS1(2048)
	//if err!=nil{
	//	t.Log(err)
	//	return
	//}
	//fmt.Println(string(privateKeyByte))
	//fmt.Println(string(publicKeyByte))
}

func TestRSAEncryptAndRSADecrypt(t *testing.T) {
	plainText := []byte("TestRSAEncryptAndRSADecrypt")
	t.Logf("rsa 加密前的明文为：%s\n", plainText)

	privateKeyByte, publicKeyByte, err := GenRSAKeyWithPKCS1(2048)
	if err != nil {
		t.Log(err)
		return
	}

	cipherText := RSAEncrypt(plainText, publicKeyByte, "public.pem")
	t.Logf("rsa 加密后的密文为：%s\n", string(cipherText))
	plainText2 := RSADecrypt(cipherText, privateKeyByte, "private.pem")
	t.Logf("rsa 解密后的明文为：%s\n", string(plainText2))
}

func TestRSASignAndVerify(t *testing.T) {
	privateKeyByte, publicKeyByte, err := GenRSAKeyWithPKCS1(2048)
	if err != nil {
		t.Log(err)
		return
	}
	privateKey, err := ParsePrivateKey(privateKeyByte)
	if err != nil {
		t.Log(err)
		return
	}
	publicKey, err := ParsePublicKey(publicKeyByte)
	if err != nil {
		t.Log(err)
		return
	}
	data := "TestRSASignAndVerify"
	sign, err := RSASign(data, privateKey, "RSA2")
	if err != nil {
		t.Log(err)
		return
	}
	t.Logf("sign:%s\n", sign)
	t.Log(RSAVerify(data, publicKey, sign, "RSA2"))

}

func TestEcdsa(t *testing.T) {
	// 随机key
	randKey := "fb0f7279c18d4394594fc9714797c9680335a320"
	// 创建公钥和私钥
	prk, puk, err := GenerateEcdsaKey(randKey)
	if err != nil {
		t.Log(err)
		return
	}

	// hash加密使用md5用到的salt
	salt := "131ilzaw"
	// 待加密的明文
	text := "TestEcdsa"
	// hash取值
	hashCipherText := hashEncrypt(text, salt)
	//hash值编码输出
	t.Log(hex.EncodeToString(hashCipherText))

	// hash值进行签名
	// 随机熵，用于加密安全
	randSign := "fb0f7279c18d439459"
	result, err := EcdsaSign(hashCipherText, randSign, prk)
	if err != nil {
		t.Log(err)
		return
	}
	// 签名输出
	t.Log(result)

	// 签名与hash值进行校验
	tmp, err := EcdsaVerify(hashCipherText, result, puk)
	t.Log(tmp)
}
