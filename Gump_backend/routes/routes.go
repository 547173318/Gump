package routes

import (
	"Gump_backend/controllers"
	"Gump_backend/logger"
	"Gump_backend/middlewares"
	"net/http"

	"github.com/gin-gonic/gin"
)

// 相当于重写了gin.Default()
func Setup(mode string) (r *gin.Engine) {

	if mode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode) // gin设置成发布模式
	}
	r = gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery(true))

	v1 := r.Group("/api/v1")
	v1.POST("/SignUp", controllers.SignUpHandle)
	v1.POST("/SignIn", controllers.SignInHandle)

	v1.GET("/hello", middlewares.JWTAuthMiddleware(), func(context *gin.Context) {
		context.String(http.StatusOK, "ok")
	})

	return
}
