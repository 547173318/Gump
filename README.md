## 1、启动方式
#### backend
```
go build main.go

main config.yaml
```
#### frontend
```
// todo
```
## 2、实现的功能
#### 2-1 数据库mysql
* sqlx包
#### 2-2 用户模块
* 注册、登入 
  * [技术总结-jwt与多点登入](https://github.com/547173318/Gump/tree/main/%E6%8A%80%E6%9C%AF%E6%80%BB%E7%BB%93)
## 3、FAQ
#### IDEA无法追踪到本地包
* 那么修改Go > Go Modules(vgo)，勾选 Enable Go Modules (vgo) integration
* proxy填：https://goproxy.cn，不然IDE无法跟踪到代码