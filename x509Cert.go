package xmcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// GetPublicKeyFromCertPath 从证书中提取公钥
// certPath 证书文件路径
func GetPublicKeyFromCertPath(certPath string) (publicKey *rsa.PublicKey, x509Cert *x509.Certificate, err error) {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return
	}
	x509Cert, err = ParseX509Certificate(string(certPEMBlock))
	if err != nil {
		return
	}
	// 获取该证书里面的公钥
	var ok bool
	publicKey, ok = x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return
	}
	return
}

// GetPublicKeyFromCertContent 从证书content中提取公钥
// certContent 公钥应用证书内容字符串（包含begin，end）
func GetPublicKeyFromCertContent(certContent string) (publicKey *rsa.PublicKey, x509Cert *x509.Certificate, err error) {
	x509Cert, err = ParseX509Certificate(certContent)
	if err != nil {
		return
	}
	// 获取该证书里面的公钥
	var ok bool
	publicKey, ok = x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return
	}
	return
}

// ParseX509Certificate 解析X.509编码的证书
func ParseX509Certificate(certPemStr string) (x509Cert *x509.Certificate, err error) {
	// pem解码
	block, _ := pem.Decode([]byte(certPemStr))
	x509Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	return
}

// GetPemCert 将证书字符串转换为Cert证书格式
func GetPemCert(rawCert string) string {
	certPemStr := "-----BEGIN CERTIFICATE-----\n"
	strlen := len(rawCert)
	for i := 0; i < strlen; i += 76 {
		if i+76 >= strlen {
			certPemStr += rawCert[i:] + "\n"
		} else {
			certPemStr += rawCert[i:i+76] + "\n"
		}
	}
	certPemStr += "-----END CERTIFICATE-----"
	return certPemStr
}