package xmcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"strings"
)

const (
	// CertificatePrefix 证书前后缀标识
	CertificatePrefix = "-----BEGIN CERTIFICATE-----"
	CertificateSuffix = "-----END CERTIFICATE-----"
)

// GetPublicKeyFromCertPath 从证书中提取公钥
// certPath 证书文件路径
func GetPublicKeyFromCertPath(certPath string) (publicKey *rsa.PublicKey, x509Cert *x509.Certificate, err error) {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return
	}
	return GetPublicKeyFromCertContent(string(certPEMBlock))
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
	if block == nil {
		return
	}
	x509Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	return
}

// GetPemCert 将证书字符串转换为Cert证书格式
func GetPemCert(rawCert string) string {
	certPemStr := CertificatePrefix + "\n"
	strlen := len(rawCert)
	for i := 0; i < strlen; i += 76 {
		if i+76 >= strlen {
			certPemStr += rawCert[i:] + "\n"
		} else {
			certPemStr += rawCert[i:i+76] + "\n"
		}
	}
	certPemStr += CertificateSuffix
	return certPemStr
}

// GetCertSNFromPath 从证书中提取序列号
// certPath 证书文件路径
// certSN 返回证书序列号，SN 值是通过解析 X.509 证书文件中签发机构名称（name）以及内置序列号（serialNumber），
// 将二者拼接后的字符串计算 MD5 值获取，可参考开放平台 SDK 源码：
func GetCertSNFromPath(certPath string) (certSN string, publicKey *rsa.PublicKey, err error) {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return
	}

	return GetCertSNFromContent(string(certPEMBlock))
}

// GetCertSNFromContent 从证书中提取序列号
// certContent 公钥应用证书内容字符串（包含begin，end）
// certSN 返回证书序列号，SN 值是通过解析 X.509 证书文件中签发机构名称（name）以及内置序列号（serialNumber），
// 将二者拼接后的字符串计算 MD5 值获取，可参考开放平台 SDK 源码：
func GetCertSNFromContent(certContent string) (certSN string, publicKey *rsa.PublicKey, err error) {

	var x509Cert *x509.Certificate

	publicKey, x509Cert, err = GetPublicKeyFromCertContent(certContent)
	if err != nil {
		return
	}

	// 证书序列号的计算
	certSN = Md51(x509Cert.Issuer.String() + x509Cert.SerialNumber.String())

	return
}

// GetRootCertSNFromPath 提取根证书序列号
// rootCertPath 根证书文件地址
// certSN 返回证书序列号，SN 值是通过解析 X.509 证书文件中签发机构名称（name）以及内置序列号（serialNumber），
// 将二者拼接后的字符串计算 MD5 值获取，可参考开放平台 SDK 源码：
func GetRootCertSNFromPath(rootCertPath string) (rootCertSN string, err error) {
	certPEMBlock, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return
	}
	return GetRootCertSNFromContent(string(certPEMBlock))
}

// GetRootCertSNFromContent 获取根证书序列号
// rootCertContent 根证书文件内容
// certSN 返回证书序列号，SN 值是通过解析 X.509 证书文件中签发机构名称（name）以及内置序列号（serialNumber），
// 将二者拼接后的字符串计算 MD5 值获取，可参考开放平台 SDK 源码：
func GetRootCertSNFromContent(rootCertContent string) (rootCertSN string, err error) {
	certStrSlice := strings.Split(rootCertContent, CertificateSuffix)
	var rootCertSnSlice []string
	for _, v := range certStrSlice {
		x509Cert, _ := ParseX509Certificate(v + CertificateSuffix)
		if x509Cert == nil || x509Cert.SignatureAlgorithm != x509.SHA1WithRSA && x509Cert.SignatureAlgorithm != x509.SHA256WithRSA {
			continue
		}
		// 证书序列号的计算
		certSN := Md51(x509Cert.Issuer.String() + x509Cert.SerialNumber.String())
		rootCertSnSlice = append(rootCertSnSlice, certSN)
	}
	if len(rootCertSnSlice) > 0 {
		rootCertSN = strings.Join(rootCertSnSlice, "_")
	}
	return
}
