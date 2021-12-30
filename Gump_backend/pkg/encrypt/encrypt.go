package encrypt

import (
	"crypto/md5"
	"encoding/hex"
)

var secret = "lch"

// encryptPassword 密码加密
func EncryptPassword(oPassword string) string {
	h := md5.New()
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum([]byte(oPassword)))
}
