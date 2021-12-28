package main

import (
	"Gump_backend/dao/mysql"
	"Gump_backend/logger"
	"Gump_backend/routes"
	"Gump_backend/settings"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

func main() {
	// 检查命令行参数
	if len(os.Args) < 2 {
		fmt.Printf("需要指定配置文件\n")
		return
	}

	// 初始化配置文件
	if err := settings.Init(os.Args[1]); err != nil {
		fmt.Printf("init settings failed,err:%v\n", err)
		return
	}

	// 初始化日志
	if err := logger.Init(settings.Conf.LogConfig); err != nil {
		fmt.Printf("init logger failed,err:%v\n", err)
		return
	}
	defer zap.L().Sync() // flushing any buffered log entries
	zap.L().Debug("zap init success")

	// 初始化MySql连接
	if err := mysql.Init(settings.Conf.MysqlConfig); err != nil {
		fmt.Printf("init mysql failed,err:%v\n", err)
		return
	}
	defer mysql.Close()

	//// 初始化Redis连接
	//if err := redis.Init(settings.Conf.RedisConfig); err != nil {
	//	fmt.Printf("init redis failed,err:%v\n", err)
	//	return
	//}
	//defer redis.Close()

	// 注册路由
	r := routes.Setup()

	// 启动服务（优雅关机）
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", settings.Conf.Port),
		Handler: r,
	}

	go func() { // 开启一个goroutine启动服务，优雅处理完
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// 创建一个通道，容量为1，只接受后面定义的信号
	quit := make(chan os.Signal, 1)
	// 定义了只会将这两种信号传给quit，不会阻塞
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// 阻塞的地方,之后代码就是关闭服务器相关的了操作了
	<-quit

	zap.L().Info("Shutdown Server...")

	// 创建一个5秒超时的context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 5秒内优雅关闭服务（将未处理完的请求处理完再关闭服务），超过5秒就超时退出
	if err := srv.Shutdown(ctx); err != nil {
		zap.L().Fatal("Server Shutdown: ", zap.Error(err))
	}

	zap.L().Info("Server exiting")
}
