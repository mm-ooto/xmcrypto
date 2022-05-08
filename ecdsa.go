package xmcrypto

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)
// ECDSA为椭圆曲线加密算法（非对称加密），是基于椭圆方程公式，所以安全性要高于RSA

// GenerateEcdsaKey 通过一个随机key创建公钥和私钥
// 随机key至少为36位
func GenerateEcdsaKey(randKey string) (privateKey *ecdsa.PrivateKey, publicKey ecdsa.PublicKey, err error) {
	var curve elliptic.Curve // 椭圆曲线参数
	length := len(randKey)
	if length < 224/8+8 {
		err = errors.New("随机key长度太短，至少为36位！")
		return
	} else if length > 521/8+8 {
		curve = elliptic.P521()
	} else if length > 384/8+8 {
		curve = elliptic.P384()
	} else if length > 256/8+8 {
		curve = elliptic.P256()
	} else if length > 224/8+8 {
		curve = elliptic.P224()
	}
	// 生成密钥对
	privateKey, err = ecdsa.GenerateKey(curve, strings.NewReader(randKey))
	if err != nil {
		return
	}
	publicKey = privateKey.PublicKey
	return
}

// EcdsaSign 对text加密，text必须是一个hash值，例如md5、sha1等
// privateKey私钥，randSign 随机熵增强加密安全，安全依赖于此熵
// 返回加密结果，结果为数字证书r、s的序列化后拼接，然后用hex转换为string
func EcdsaSign(text []byte, randSign string, privateKey *ecdsa.PrivateKey) (string, error) {
	r, s, err := ecdsa.Sign(strings.NewReader(randSign), privateKey, text)
	if err != nil {
		return "", err
	}
	rt, err := r.MarshalText()
	if err != nil {
		return "", err
	}
	st, err := s.MarshalText()
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	defer w.Close()
	_, err = w.Write([]byte(string(rt) + "+" + string(st)))
	w.Flush()
	return hex.EncodeToString(b.Bytes()), nil
}

// getEcdsaSign 证书分解
// 通过hex解码，分割成数字证书r，s
func getEcdsaSign(signature string) (rInt, sInt big.Int, err error) {
	byterun, err := hex.DecodeString(signature)
	if err != nil {
		err = errors.New("decrypt error, " + err.Error())
		return
	}
	r, err := gzip.NewReader(bytes.NewBuffer(byterun))
	if err != nil {
		err = errors.New("decode error," + err.Error())
		return
	}
	defer r.Close()
	buf := make([]byte, 1024)
	count, err := r.Read(buf)
	if err != nil {
		err = errors.New("decode read error," + err.Error())
		return
	}
	rs := strings.Split(string(buf[:count]), "+")
	if len(rs) != 2 {
		err = errors.New("decode fail")
		return
	}
	err = rInt.UnmarshalText([]byte(rs[0]))
	if err != nil {
		err = errors.New("decrypt rInt fail, " + err.Error())
		return
	}
	err = sInt.UnmarshalText([]byte(rs[1]))
	if err != nil {
		err = errors.New("decrypt sInt fail, " + err.Error())
		return
	}
	return
}

// EcdsaVerify 校验文本内容是否与签名一致
// 使用公钥校验签名和文本内容
func EcdsaVerify(text []byte, signature string, key ecdsa.PublicKey) (bool, error) {

	rInt, sInt, err := getEcdsaSign(signature)
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(&key, text, &rInt, &sInt)
	return result, nil

}

// hash加密，使用md5加密
// plainText 要加密的明文，salt 盐
func hashEncrypt(plainText, salt string) []byte {

	Md5Inst := md5.New()
	Md5Inst.Write([]byte(plainText))
	result := Md5Inst.Sum([]byte(salt))

	return result
}
