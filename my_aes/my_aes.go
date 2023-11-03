package my_aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"socks5_mitm/pkg/shadowsocks2/shadowaead"
)

func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)

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

// BytesToHex 将字节数组转换为16进制字符串
func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// HexToBytes 将16进制字符串转换为字节数组
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
