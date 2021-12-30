package mysql

import (
	"Gump_backend/models"
	"Gump_backend/pkg/encrypt"
	"database/sql"
)

// CheckUserExist 检查指定用户名的用户是否存在
func CheckUserExist(Username string) (err error) {
	sqlStr := "select count(user_id) from user where username= ?"
	var count int64
	if err := db.Get(&count, sqlStr, Username); err != nil {
		return err
	}
	if count > 0 {
		return ErrorUserExist
	}
	return
}

// InsertUser 想数据库中插入一条新的用户记录
func InsertUser(user *models.User) (err error) {
	// 对密码进行加密
	user.Password = encrypt.EncryptPassword(user.Password)
	// 执行SQL语句入库
	sqlStr := `insert into user(user_id, username, password) values(?,?,?)`
	_, err = db.Exec(sqlStr, user.UserID, user.Username, user.Password)
	return
}

// 用户登入
func SignIn(user *models.User) (err error) {
	oPassword := user.Password
	// 判断用户是否存在
	sqlStr := "select user_id,username,password from user where username=?"
	if err = db.Get(user, sqlStr, user.Username); err != nil {
		if err == sql.ErrNoRows { // 用户不存在
			return ErrorUserNotExist
		}
		return // 数据库出错
	}
	// 比较登入密码
	password := encrypt.EncryptPassword(oPassword)
	if password != user.Password { // 用户名或密码错误
		return ErrorInvalidPassword
	}
	return
}
