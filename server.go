package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/clong1995/go-ansi-color"
	"github.com/clong1995/go-auth"
	"github.com/clong1995/go-client"
	"github.com/clong1995/go-config"
	"github.com/clong1995/go-db-kv"
	"github.com/pkg/errors"
)

var prefix = "gateway"

var server *http.Server

// 过期时间,超期拒绝,重放清除
var out int64 = 60

var configServer map[string]string

func init() {
	start()
}

func start() {
	var exists bool
	if configServer, exists = config.Value[map[string]string]("SERVER"); !exists || len(configServer) == 0 {
		pcolor.PrintFatal(prefix, "server empty")
		return
	}

	//ssl
	pem, key, err := sslPem()
	if err != nil {
		pcolor.PrintFatal(prefix, err.Error())
		return
	}

	//server
	server = &http.Server{
		IdleTimeout: 90 * time.Second,
	}
	if pem == "" || key == "" {
		server.Addr = ":80"
	} else {
		server.Addr = ":443"
	}
	http.HandleFunc("/", routeHandle)

	pcolor.PrintSucc(prefix, "listening %s\n", server.Addr)

	go func() {
		if pem == "" || key == "" {
			if err = server.ListenAndServe(); err != nil {
				pcolor.PrintFatal(prefix, err.Error())
				return
			}
		} else {
			if err = server.ListenAndServeTLS(pem, key); err != nil {
				pcolor.PrintFatal(prefix, err.Error())
				return
			}
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			pcolor.PrintFatal(prefix, err.Error())
			return
		}

		//优雅关闭
		pcolor.PrintSucc(prefix, "server exited!")
	}()

	return
}

func routeHandle(w http.ResponseWriter, r *http.Request) {
	var err error
	var code int

	var userId int64
	var req []byte
	var res []byte

	requestPath := r.URL.Path
	//难免会有带参数的地址虽然很少
	requestRawPath := requestPath
	if r.URL.RawQuery != "" {
		requestRawPath += "?" + r.URL.RawQuery
	}

	defer func() {
		_ = r.Body.Close()
		//处理错误
		var errStr string
		if err != nil {
			errStr = err.Error()
			pcolor.PrintError(prefix, errStr)
			if code == 0 {
				code = http.StatusBadRequest
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(errStr))
		}

		logCollector, exists := config.Value[string]("LOG COLLECTOR")
		if !exists || logCollector == "" {
			return
		}
		//处理日志
		ip := clientIP(r)
		go log(logCollector, ip, r.RequestURI, userId, req, res, errStr)
	}()

	//检查User-Agent
	if err = userAgent(r.Header.Get("User-Agent")); err != nil {
		code = http.StatusForbidden
		err = errors.WithStack(err)
		return
	}

	//检查uri
	domain, uriPath, err := requestPathParts(requestPath)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	//取出server地址
	serverAddr, err := route(domain)
	if err != nil {
		code = http.StatusNotFound
		return
	}

	//读取body
	if req, err = io.ReadAll(r.Body); err != nil {
		err = errors.WithStack(err)
		code = http.StatusServiceUnavailable
		return
	}

	//签名是否存在
	sign := r.Header.Get("content-sign")
	if sign == "" {
		err = errors.New("missing data signature")
		code = http.StatusUnauthorized
		return
	}

	//检查请求签名和提取ak
	ak, err := auth.Check(sign, out, append(req, requestRawPath...))
	if err != nil {
		code = http.StatusUnauthorized
		err = errors.WithStack(err)
		return
	}

	//获取用户id和请求的session
	userId, session_, err := auth.ID(ak)
	if err != nil {
		code = http.StatusUnauthorized
		return
	}

	//限速
	if err = limit(requestRawPath, userId); err != nil {
		code = http.StatusBadRequest
		return
	}

	//防止重放攻击
	if err = replay(sign, userId); err != nil {
		code = http.StatusBadRequest
		return
	}

	//session和权限验证
	if err = verify(userId, session_, requestPath); err != nil {
		code = http.StatusUnauthorized
		return
	}

	//转发
	if res, err = relay(serverAddr+"/"+uriPath, userId, req); err != nil {
		return
	}

	//签名结果
	if sign, err = auth.Sign(append(res, requestRawPath...), ak); err != nil {
		code = http.StatusUnauthorized
		return
	}

	w.Header().Set("content-sign", sign)

	//返回结果
	_, _ = w.Write(res)
}

func Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		pcolor.PrintError(prefix, err.Error())
	}
}

func clientIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

// (pem, key string,err error)
func sslPem() (string, string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	dir := filepath.Dir(exePath)
	//现寻找程序运行目录
	sslPath := path.Join(dir, "ssl")
	if _, err = os.Stat(sslPath); err != nil {
		//再寻找代码目录
		dir, err = os.Getwd()
		if err != nil {
			return "", "", errors.WithStack(err)
		}
		sslPath = path.Join(dir, "ssl")
		if _, err = os.Stat(sslPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", "", nil
			}
			return "", "", errors.WithStack(err)
		}
	}

	entries, err := os.ReadDir(sslPath)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	if len(entries) < 2 { //文件不在
		return "", "", nil
	}

	var pemPath, keyPath string
	for _, entry := range entries {
		// 忽略目录，只处理文件
		if entry.IsDir() {
			continue
		}
		fileName := entry.Name()
		ext := strings.ToLower(filepath.Ext(fileName))
		// 匹配 .pem 文件（仅在尚未找到时赋值）
		if ext == ".pem" && pemPath == "" {
			pemPath = filepath.Join(sslPath, fileName)
		}
		// 匹配 .key 文件（仅在尚未找到时赋值）
		if ext == ".key" && keyPath == "" {
			keyPath = filepath.Join(sslPath, fileName)
		}
		// 性能优化：如果两个文件都找到了，提前退出循环
		if pemPath != "" && keyPath != "" {
			break
		}
	}

	return pemPath, keyPath, nil
}

func userAgent(userAgent string) error {
	if userAgent == "" {
		return errors.New("user agent empty")
	}
	configUserAgent, _ := config.Value[string]("USER AGENT")

	if !strings.HasPrefix(userAgent, configUserAgent) {
		return errors.New("user agent illegal")
	}
	return nil
}

// (domain, path string, err error)
func requestPathParts(requestPath string) (domain, path string, err error) {
	if requestPath == "" || requestPath == "/" {
		return "", "", errors.New("route empty")
	}
	parts := strings.Split(requestPath, "/")
	if len(parts) < 2 {
		return "", "", errors.New("route empty")
	}
	domain = parts[1]
	path = strings.Join(parts[2:], "/")
	return
}

// 限流
func limit(path string, userId int64) error {
	key := kv.HashKey(fmt.Sprintf("%s_%d", path, userId))
	exists, err := kv.Exists(key, 400)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("limit exists")
	}
	return nil
}

// 重放攻击
func replay(sign string, id int64) error {
	hashKey := kv.HashKey(fmt.Sprintf("%s_%d", sign, id))
	exists, err := kv.Exists(hashKey, (out+1)*1000)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("disable replay")
	}
	return nil
}

func verify(uid, session int64, path string) error {
	access, exists := config.Value[string]("ACCESS")
	if !exists {
		//没配置验证服务不需要验证
		return nil
	}
	if _, err := client.Do[any](uid, access+"/gob/session/get",
		http.MethodPost,
		struct {
			Session int64
			Path    string
		}{
			session,
			path,
		}, client.GOB); err != nil {
		return err
	}
	return nil
}

// 转发
func relay(apiURL string, userId int64, req []byte) ([]byte, error) {
	res, err := client.Do[[]byte](1, apiURL, http.MethodPost, req, client.BYTES, map[string]any{
		"user-id": userId,
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func route(key string) (string, error) {
	if value, ok := configServer[key]; ok {
		if len(value) == 0 {
			return "", errors.New("route is empty")
		}
		return value, nil
	}

	return "", errors.Errorf("no found route : %s", key)
}

// 记录log
type data struct {
	Ip       string
	Uri      string
	Uid      int64
	Request  []byte
	Response []byte
	Error    string
}

func log(logCollector string, realIP string, uri string, uid int64, req []byte, res []byte, errStr string) {
	d := data{
		Ip:       realIP,
		Uri:      uri,
		Uid:      uid,
		Request:  req,
		Response: res,
		Error:    errStr,
	}
	if _, err := client.Do[any](1, logCollector+"/gob/post", http.MethodPost, d, client.GOB); err != nil {
		//TODO 输出异常
		return
	}
}
