package logic

import (
	"Gump_backend/dao/mysql"
	"Gump_backend/models"
	model "Gump_backend/models"
	"Gump_backend/pkg/jwt"
	"Gump_backend/pkg/snowflake"
)

func SignUp(p *model.SignUpParam) (err error) {
	// 1、判断用户是否存在
	if err := mysql.CheckUserExist(p.Username); err != nil {
		return err
	}
	// 2、生成UID
	userID := snowflake.GenID()
	user := &model.User{
		UserID:   userID,
		Username: p.Username,
		Password: p.Password,
	}
	// 3、插入数据库
	return mysql.InsertUser(user)
}

func SignIn(p *model.SignInParam) (user *models.User, err error) {
	user = &models.User{
		Username: p.Username,
		Password: p.Password,
	}
	if err = mysql.SignIn(user); err != nil {
		return nil, err
	}

	token, err := jwt.GenToken(user.UserID, user.Username)
	if err != nil {
		return
	}
	user.Token = token
	return
}
