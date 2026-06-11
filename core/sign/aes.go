//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/sign：AES-GCM / AES-CBC-PKCS#7 加解密——平台回调密文与敏感数据解密
//2026/6/11
//***************************************************

package sign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AESGCMEncrypt AES-GCM 加密（AEAD）。key 长度 16/24/32 字节对应 AES-128/192/256；
// nonce 长度必须等于 GCM 标准 nonce 长度（12 字节）；aad 为附加认证数据，可为 nil。
// 返回 密文||认证标签（Go 标准库 Seal 的默认形态）。
func AESGCMEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("sign: GCM nonce 长度必须为 %d 字节（实际 %d）", gcm.NonceSize(), len(nonce))
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// AESGCMDecrypt AES-GCM 解密（AEAD）。ciphertext 为 密文||认证标签；
// 认证失败（密钥错 / 数据被篡改 / aad 不匹配）返回错误。
func AESGCMDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("sign: GCM nonce 长度必须为 %d 字节（实际 %d）", gcm.NonceSize(), len(nonce))
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("sign: AES-GCM 解密失败（密钥/nonce/aad 不匹配或数据被篡改）: %w", err)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sign: AES 密钥非法（长度须为 16/24/32 字节）: %w", err)
	}
	return cipher.NewGCM(block)
}

// AESCBCEncryptPKCS7 AES-CBC 加密，明文按 PKCS#7 填充。iv 长度必须为 16 字节。
func AESCBCEncryptPKCS7(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sign: AES 密钥非法（长度须为 16/24/32 字节）: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("sign: CBC iv 长度必须为 %d 字节（实际 %d）", aes.BlockSize, len(iv))
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// AESCBCDecryptPKCS7 AES-CBC 解密并去除 PKCS#7 填充。
// 注意：CBC 无认证，仅当平台协议在密文之外另有签名/MAC 保护时才可使用；
// 填充非法返回错误。
func AESCBCDecryptPKCS7(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sign: AES 密钥非法（长度须为 16/24/32 字节）: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("sign: CBC iv 长度必须为 %d 字节（实际 %d）", aes.BlockSize, len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("sign: CBC 密文长度必须为 %d 的非零整数倍（实际 %d）", aes.BlockSize, len(ciphertext))
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, aes.BlockSize)
}

// pkcs7Pad 按 PKCS#7 规则填充到 blockSize 整数倍。
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// pkcs7Unpad 去除 PKCS#7 填充；填充字节非法时返回错误。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("sign: PKCS#7 数据长度非法")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("sign: PKCS#7 填充长度非法")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("sign: PKCS#7 填充内容非法")
		}
	}
	return data[:len(data)-padLen], nil
}
