package controllers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const CtxUserIDKey = "userID"

var ErrorUserNotLogin = errors.New("用户未登录")

// getCurrentUserID 获取当前登录的用户ID
func getCurrentUserID(context *gin.Context) (userID int64, err error) {
	uID, ok := context.Get(CtxUserIDKey)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	userID, ok = uID.(int64)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	return
}
