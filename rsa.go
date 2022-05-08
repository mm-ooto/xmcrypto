package xmcrypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
)

// rsa是非对称加密，非对称加密是通过两个密钥（公钥-私钥）来实现对数据的加密和解密的。公钥用于加密，私钥用于解密
// 优点：与对称加密相比，安全性更好，加解密需要不同的密钥，公钥和私钥都可进行相互的加解密。
// 缺点：加密和解密花费时间长、速度慢，只适合对少量数据进行加密。
// 应用场景：适合于对安全性要求很高的场景，适合加密少量数据，比如支付数据、登录数据等。

const (
	PublicKeyType     = "PUBLIC KEY"
	PrivateKeyType    = "PRIVATE KEY"
	RSAPrivateKeyType = "RSA PRIVATE KEY"
)

// GenRSAKeyWithPKCS1 生成RSA私钥和公钥
func GenRSAKeyWithPKCS1(bits int) (privateKeyByte, publicKeyByte []byte, err error) {
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥。
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}

	// x509对私钥编码
	// MarshalPKCS1PrivateKey将rsa私钥序列化为ASN.1 PKCS#1 DER编码。
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privKey)
	// 构建一个pem.Block结构体对象
	privateBlock := pem.Block{
		Type:  RSAPrivateKeyType,
		Bytes: x509PrivateKey,
	}
	// pem编码同时将数据保存到priBuf
	var priBuf bytes.Buffer
	pem.Encode(&priBuf, &privateBlock)
	privateKeyByte = priBuf.Bytes()
	//
	pubBytes, err := getPublicKeyBytes(&privKey.PublicKey)
	if err != nil {
		return
	}
	publicKeyByte = pubBytes
	return
}

func getPublicKeyBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pubBlock := &pem.Block{Type: PublicKeyType, Bytes: pubDer}

	var pubBuf bytes.Buffer
	if err = pem.Encode(&pubBuf, pubBlock); err != nil {
		return nil, err
	}
	return pubBuf.Bytes(), nil
}

// GenerateRSAKey 生成RSA私钥和公钥，保存到文件中
// bits 证书大小
func GenerateRSAKey(bits int) {
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥。
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	// x509对私钥编码
	// MarshalPKCS1PrivateKey将rsa私钥序列化为ASN.1 PKCS#1 DER编码。
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	// 创建文件保存私钥
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	// 构建一个pem.Block结构体对象
	privateBlock := pem.Block{
		Type:  RSAPrivateKeyType,
		Bytes: x509PrivateKey,
	}
	// pem编码同时将数据保存到文件
	pem.Encode(privateFile, &privateBlock)

	// 保存公钥
	// 获取公钥数据
	publicKey := privateKey.PublicKey
	// x509对公钥编码
	// MarshalPKIXPublicKey将公钥序列化为PKIX格式DER编码。
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	// 创建文件保存私钥
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
	// 构建一个pem.Block结构体对象
	publicBlock := pem.Block{
		Type:  PublicKeyType,
		Bytes: x509PublicKey,
	}
	// pem编码同时将数据保存到文件
	pem.Encode(publicFile, &publicBlock)
}

// ParsePrivateKey 解析私钥
func ParsePrivateKey(privateKeyByte []byte) (privateKey *rsa.PrivateKey, err error) {
	// pem解码
	block, _ := pem.Decode(privateKeyByte)
	// x509解码
	// ParsePKCS1PrivateKey解析ASN.1 PKCS#1 DER编码的rsa私钥。
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

// ParsePublicKey 解析公钥
func ParsePublicKey(publicKeyByte []byte) (publicKey *rsa.PublicKey, err error) {
	// pem解码
	block, _ := pem.Decode(publicKeyByte)
	// x509解码
	// ParsePKIXPublicKey解析一个DER编码的公钥。这些公钥一般在以"BEGIN PUBLIC KEY"出现的PEM块中
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	publicKey = publicKeyInterface.(*rsa.PublicKey)
	return
}

// GetPrivateKeyFromFile 从文件中读取私钥和公钥
func GetPrivateKeyFromFile(filePath string) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	// 读取文件内容
	fileInfo, _ := file.Stat()
	buff := make([]byte, fileInfo.Size())
	file.Read(buff)
	// 解析私钥
	privateKey, err = ParsePrivateKey(buff)

	// 从私钥中获取公钥
	publicKey = &privateKey.PublicKey

	return
}

// GetPublicKeyFromFile 从文件中读取公钥
func GetPublicKeyFromFile(filePath string) (publicKey *rsa.PublicKey, err error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// 读取文件内容
	fileInfo, _ := file.Stat()
	buff := make([]byte, fileInfo.Size())
	file.Read(buff)
	// 解析
	publicKey, err = ParsePublicKey(buff)
	return
}

// RSAEncrypt RSA公钥加密
// plainText要加密的数据,publicKeyByte公钥数据，path公钥文件地址，注意：publicKeyByte和filePath二选一
func RSAEncrypt(plainText, publicKeyByte []byte, filePath string) []byte {
	var publicKey *rsa.PublicKey
	var err error
	if publicKeyByte != nil {
		publicKey, err = ParsePublicKey(publicKeyByte)
	} else {
		publicKey, err = GetPublicKeyFromFile(filePath)
	}
	if err != nil {
		panic(err)
	}

	// 对明文进行加密
	// EncryptPKCS1v15使用PKCS#1 v1.5规定的填充方案和RSA算法加密msg
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// RSADecrypt RSA私钥解密
// cipherText要解密的数据，privateKeyByte私钥数据，filePath私钥文件地址，注意：privateKeyByte和filePath二选一
func RSADecrypt(cipherText, privateKeyByte []byte, filePath string) []byte {
	var privateKey *rsa.PrivateKey
	var err error
	if privateKeyByte != nil {
		privateKey, err = ParsePrivateKey(privateKeyByte)
	} else {
		privateKey, _, err = GetPrivateKeyFromFile(filePath)
	}
	if err != nil {
		panic(err)
	}

	// 对明文进行解密
	// DecryptPKCS1v15使用PKCS#1 v1.5规定的填充方案和RSA算法解密密文
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		panic(err)
	}
	return plainText
}

// 签名和验签

// RSASign 签名
// data 排序后的待签名字符串
// rsaType签名算法类型：可选值（RSA,RSA2）
func RSASign(data string, rsaPrivateKey *rsa.PrivateKey, rsaType string) (string, error) {
	hashP := crypto.SHA256
	if rsaType == "RSA" {
		hashP = crypto.SHA1
	}
	hash := hashP.New()
	hash.Write([]byte(data))
	sign, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, hashP, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	// base64编码
	signByte := base64.StdEncoding.EncodeToString(sign)
	return signByte, nil
}

// RSAVerify 验签
// data 排序后的待签名字符串
func RSAVerify(data string, rsaPublicKey *rsa.PublicKey, signData string, rsaType string) (err error) {
	hashP := crypto.SHA256
	if rsaType == "RSA" {
		hashP = crypto.SHA1
	}
	// base64解码
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	hash := hashP.New()
	hash.Write([]byte(data))
	return rsa.VerifyPKCS1v15(rsaPublicKey, hashP, hash.Sum(nil), sign)
}
