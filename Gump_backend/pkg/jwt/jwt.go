package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/viper"
)

var mySecret = []byte("lch")

// MyClaims自定义声明结构体并内嵌jwt.StandardClaims
// jwt包自带的jwt.StandardClaims只包含了官方字段
// 我们这里需要额外记录一个username字段，所以要自定义结构体
// 如果想要保存更多信息，都可以添加到这个结构体中
type myClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// GenToken 生成JWT
func GenToken(userID int64, username string) (string, error) {
	// 1、声明一个自己的数据
	c := myClaims{
		userID,
		username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(
				time.Duration(viper.GetInt("auth.jwt_expire")) * time.Hour).Unix(), // 过期时间
			Issuer: "Gump", // 签发人
		},
	}
	// 2、创建签名对象
	//jwt.SigningMethodES256 两种类型 *SigningMethodECDSA 和 *SigningMethodHMAC
	//jwt := jwt.NewWithClaims(jwt.SigningMethodES256, c) // SigningMethodES256 *SigningMethodECDSA  此类型会报错： key is of invalid type`
	//jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, c) // SigningMethodHS256 *SigningMethodHMAC 不报错
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	// 3、使用指定的secret签名并获得完整的编码后的字符串token
	return token.SignedString(mySecret)
}

// ParseToken 解析JWT
func ParseToken(tokenString string) (*myClaims, error) {
	// 1、解析token
	var mc = new(myClaims)
	// 2、验证该token是否是有效的token，将结果存到token.Valid，其中关于回调函数，官方的注释如下：
	// Parse methods use this callback function to supply
	// the key for verification.  The function receives the parsed,
	// but unverified Token.  This allows you to use properties in the
	// Header of the token (such as `kid`) to identify which key to use.
	token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (i interface{}, err error) {
		return mySecret, nil
	})
	if err != nil {
		return nil, err
	}
	if token.Valid { // 校验token
		return mc, nil
	}
	return nil, errors.New("invalid token")
}
