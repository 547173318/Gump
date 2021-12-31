package controllers

import (
	"Gump_backend/dao/mysql"
	"Gump_backend/logic"
	model "Gump_backend/models"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/go-playground/validator/v10"

	"github.com/gin-gonic/gin"
)

func SignUpHandle(context *gin.Context) {
	// 1、参数处理
	p := new(model.SignUpParam)

	if err := context.ShouldBindJSON(p); err != nil {
		// 请求参数有误，直接返回响应
		zap.L().Error("SignUp with invalid param", zap.Error(err))
		// 判断err是不是validator.ValidationErrors 类型
		err2, ok := err.(validator.ValidationErrors)
		if !ok { // validator.ValidationError
			ResponseError(context, CodeInvalidParam)
			return
		}
		ResponseErrorWithMsg(context, CodeInvalidParam, err2.Error())
		return
	}
	// 2、逻辑处理
	if err := logic.SignUp(p); err != nil {
		zap.L().Error("logic.SignUp failed", zap.Error(err))
		if errors.Is(err, mysql.ErrorUserExist) {
			ResponseError(context, CodeUserExist)
			return
		}
		ResponseError(context, CodeServerBusy)
		return
	}
	// 3、结构返回
	ResponseSuccess(context, nil)
}

func SignInHandle(context *gin.Context) {
	// 1、参数校验
	p := new(model.SignInParam)
	if err := context.ShouldBindJSON(p); err != nil {
		// 请求参数有误，直接返回响应
		zap.L().Error("SignIn with invalid param", zap.Error(err))
		// 判断err是不是validator.ValidationErrors 类型
		err2, ok := err.(validator.ValidationErrors)
		if !ok {
			ResponseError(context, CodeInvalidParam)
			return
		}
		ResponseErrorWithMsg(context, CodeInvalidParam, err2.Error())
		return
	}
	// 2、业务逻辑
	user, err := logic.SignIn(p)
	if err != nil {
		zap.L().Error("logic.SignIn failed", zap.Error(err))
		if errors.Is(err, mysql.ErrorUserNotExist) { // err为ErrorUserNotExist，用户不存在
			ResponseError(context, CodeUserNotExist)
			return
		} else if errors.Is(err, mysql.ErrorInvalidPassword) { // 密码错误
			ResponseError(context, CodeInvalidPassword)
			return
		} else { // 数据库执行出错
			ResponseError(context, CodeServerBusy)
			return
		}
	}
	// 3.返回响应
	ResponseSuccess(context, gin.H{
		"user_id":   fmt.Sprintf("%d", user.UserID), // id值大于1<<53-1  int64类型的最大值是1<<63-1
		"user_name": user.Username,
		"token":     user.Token,
	})
}
