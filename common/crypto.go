package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func GenerateHMACWithKey(key []byte, data string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateHMAC(data string) string {
	h := hmac.New(sha256.New, []byte(CryptoSecret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Password2Hash 将明文密码转换为存储格式
// 如果 PlaintextPasswordEnabled=true，返回明文（不添加前缀）
// 如果 PlaintextPasswordEnabled=false，返回 bcrypt 加密哈希
func Password2Hash(password string) (string, error) {
	if PlaintextPasswordEnabled {
		// ⚠️ 安全警告：明文存储模式
		// 不再添加 "PLAIN:" 前缀
		return password, nil
	}

	// 默认使用 bcrypt 加密
	passwordBytes := []byte(password)
	hashedPassword, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	return string(hashedPassword), err
}

// ValidatePasswordAndHash 验证密码是否匹配
// 自动识别明文密码（无前缀）和 bcrypt 哈希
func ValidatePasswordAndHash(password string, hash string) bool {
	// 当启用明文存储且密码不以$2开头（bcrypt哈希特征）时，认为是明文密码
	if PlaintextPasswordEnabled && (len(hash) < 2 || hash[:2] != "$2") {
		// 明文密码比对
		return password == hash
	}

	// bcrypt 密码比对
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
