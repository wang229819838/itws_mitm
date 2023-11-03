package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"socks5_mitm/pkg/shadowsocks2/shadowaead"
)

func main() {
	_, c, err := EVP_BytesToKeyChacha20Poly1305("itws@229819838", 32)
	if err != nil {
		fmt.Printf("EVP_BytesToKeyChacha20Poly1305: %v\n", err)
		return
	}
	// plaintext := []byte(`itws aes`)
	// dst := make([]byte, 4096)
	// fmt.Printf("原始明文数据\n%s\n ", hex.Dump(plaintext))
	// jmData, err := shadowaead.Pack(dst, plaintext, c)
	// if err != nil {
	// 	fmt.Printf("加密数据失败  %s \n", err.Error())
	// 	return
	// }
	// fmt.Printf("加密后数据\n%s\n ", hex.Dump(jmData))
	// fmt.Println(BytesToHex(jmData))
	// if true {
	// 	return
	// }
	fmt.Println("开始解密数据...")
	// _, cc, err := my_aes.EVP_BytesToKey("123456", 16)
	// if err != nil {
	// 	fmt.Printf("EVP_BytesToKey2 : %v\n", err)
	// 	return
	// }
	jmData, _ := HexToBytes(`94dbe6c8b37ce5992193d4a0fd8a66586e4e5c9fd5095cac5c16bc54500a3dab9d5d68040a50eace93f13afab8e494fc8af897b6c508aa3ddddd3fd8183b77a968d32a89bd6783330587f55595c71c7315662b1505861e2c5e770b8466a577edfe1b5ead65ffebdf1995b2d105b4ddd121bfa1778212931a47a1f099d20326f43eb2210e5583ecdbcef9962067b41307cd6031da2d0b4cf942aee5264c49386c2fab4c83f060dffc69adfd8169761a4c1e2cea27b721b878988b452f31c13af5f332d96f74f6fdbbd25876de5c2430cdb83ca8e60960b9e75403500f9fde65b64fc434289076621fd09a058558766a740b7aba4af9fa82c7d6a0bdf52d975ac21704444e1e4433e43fe15b45b3ac3ce588649f7b9eb0ef57701f6a847346d7c6ef833d1ff3c4ff8973b2b285156c5125b22e3aeaf408c166ffe1245b25e7222daecce53d0233c229a7e4030d0f48eafd006076f9f4d2f3a3`)
	jmhData, err := shadowaead.Unpack(make([]byte, 4096), jmData, c)
	if err != nil {
		fmt.Printf("解密数据失败  %s \n", err.Error())
		return
	}
	fmt.Printf("解密后数据\n%s\n ", hex.Dump(jmhData))
}

func EVP_BytesToKey(password string, keyLen int) ([]byte, shadowaead.Cipher, error) {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	aead, err := shadowaead.AESGCM(b[:keyLen])
	return b[:keyLen], aead, err
}
func EVP_BytesToKeyChacha20Poly1305(password string, keyLen int) ([]byte, shadowaead.Cipher, error) {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	aead, err := shadowaead.Chacha20Poly1305(b[:keyLen])
	return b[:keyLen], aead, err
}

// BytesToHex 将字节数组转换为16进制字符串
func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// HexToBytes 将16进制字符串转换为字节数组
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
