package routes

import (
	"Gump_backend/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

// 相当于重写了gin.Default()
func Setup() (r *gin.Engine) {
	r = gin.New()

	r.Use(logger.GinLogger(), logger.GinRecovery(true))
	r.GET("/hello", func(context *gin.Context) {
		context.String(http.StatusOK, "ok")
	})
	return
}
