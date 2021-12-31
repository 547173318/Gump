package middlewares

import (
	"Gump_backend/controllers"
	"Gump_backend/pkg/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTAuthMiddleware 基于JWT的认证中间件
func JWTAuthMiddleware() func(context *gin.Context) {
	return func(context *gin.Context) {
		// 1、获取token
		// 客户端携带Token有三种方式 1.放在请求头 2.放在请求体 3.放在URI
		// 这里假设Token放在Header的Authorization中，并使用Bearer开头
		// Authorization: Bearer xxxxx.xxx.xxx
		authHeader := context.Request.Header.Get("Authorization")
		if authHeader == "" {
			controllers.ResponseError(context, controllers.CodeNeedLogin)
			context.Abort()
			return
		}
		// 2、检查token格式,必须是Bearer格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			controllers.ResponseError(context, controllers.CodeInvalidToken)
			context.Abort()
			return
		}
		// 3、检查token是否有效
		mc, err := jwt.ParseToken(parts[1])
		if err != nil {
			controllers.ResponseError(context, controllers.CodeInvalidToken)
			context.Abort()
			return
		}
		// 4、存储用户信息到context
		context.Set(controllers.CtxUserIDKey, mc.UserID)
		// 5、context.next
		context.Next()
	}
}
