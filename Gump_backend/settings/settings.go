package settings

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// 指针类型的全局变量
var Conf = new(AppConfig)

// 整个项目的配置信息
type AppConfig struct {
	Name    string `mapstructure:"name"`
	Mode    string `mapstructure:"mode"`
	Port    int    `mapstructure:"port"`
	Version string `mapstructure:"version"`

	*LogConfig   `mapstructure:"log"`
	*MysqlConfig `mapstructure:"mysql"`
	*RedisConfig `mapstructure:"redis"`
}

// 日志配置信息
type LogConfig struct {
	Level      string `mapstructure:"level"`
	FileName   string `mapstructure:"file_name"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxAge     int    `mapstructure:"max_age"`
	MaxBackups int    `mapstructure:"max_backups"`
}

// mysql配置信息
type MysqlConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	DbName       string `mapstructure:"dbname"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
}

// redis配置信息
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Db       int    `mapstructure:"db"`
	Password string `mapstructure:"password"`
	PoolSize int    `mapstructure:"pool_size"`
}

func Init(fileName string) (err error) {

	viper.SetConfigFile(fileName) // 指定配置文件

	if err = viper.ReadInConfig(); err != nil { // 读取配置文件
		fmt.Printf("viper.ReadInConfig failed,err:%v\n", err)
	}

	if err = viper.Unmarshal(Conf); err != nil { // 反序列化配置文件到结构体当中
		fmt.Printf("viper.Unmarshal(Conf) failed,err:%v\n", err)
		return
	}

	viper.WatchConfig()                            // 监控配置文件的变化
	viper.OnConfigChange(func(in fsnotify.Event) { // 变化后回调处理，更新结构体
		fmt.Printf("config.yaml has changed.\n")
		if err = viper.Unmarshal(Conf); err != nil { // 反序列化配置文件到结构体当中
			fmt.Printf("viper.Unmarshal(Conf) failed,err:%v\n", err)
		}
	})

	return

}
