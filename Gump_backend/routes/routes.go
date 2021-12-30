package routes

import (
	"Gump_backend/controllers"
	"Gump_backend/logger"
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
	r.GET("/hello", func(context *gin.Context) {
		context.String(http.StatusOK, "ok")
	})

	r.POST("/SignUp", controllers.SignUpHandle)
	r.POST("/SignIn", controllers.SignInHandle)
	return
}
