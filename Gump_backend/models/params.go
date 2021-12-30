package models

// 注册请求参数
type SignUpParam struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RePassword string `json:"re_password" binding:"required,eqfield=Password"`
}

// 登录请求参数
type SignInParam struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
