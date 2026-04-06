package gateway

import (
	pcolor "github.com/clong1995/go-ansi-color"
	conf "github.com/clong1995/go-config"
)

// 全局变量，用于存储从配置中读取的数据库设置
var configAddr string              // 机器id
var configUserAgent string         // user agent
var configLogCollector string      // 日志
var configAccess string            // 权限验证
var configServer map[string]string // 数据源连接字符串列表

func config() {
	var exists bool

	//
	configAddr, _ = conf.Value[string]("ADDR")

	//
	configUserAgent, _ = conf.Value[string]("USER AGENT")

	//
	configUserAgent, _ = conf.Value[string]("ACCESS")

	//
	if configServer, exists = conf.Value[map[string]string]("SERVER"); !exists || len(configServer) == 0 {
		pcolor.PrintFatal(prefix, "未找到或为空的 'SERVER' 配置")
		return
	}
}
