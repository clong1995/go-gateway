package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/clong1995/go-ansi-color"
	"github.com/clong1995/go-auth"
	"github.com/clong1995/go-client"
	"github.com/clong1995/go-db-kv"
	"github.com/pkg/errors"
)

var prefix = "gateway"

var server *http.Server

// 过期时间,超期拒绝,重放清除
var out int64 = 60

func init() {
	config()
	start()
}

func start() {
	//ssl
	pem, key, err := sslPem()
	if err != nil {
		pcolor.PrintFatal(prefix, err.Error())
		return
	}

	//server
	server = &http.Server{
		Handler:      corsMiddleware(http.DefaultServeMux),
		IdleTimeout:  90 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if configAddr == "" {
		if pem == "" || key == "" {
			server.Addr = ":80"
		} else {
			server.Addr = ":443"
		}
	} else {
		server.Addr = configAddr
	}

	http.HandleFunc("/", routeHandle)

	go func() {
		var serveErr error
		if pem == "" || key == "" {
			if serveErr = server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				pcolor.PrintFatal(prefix, serveErr.Error())
				return
			}
		} else {
			if serveErr = server.ListenAndServeTLS(pem, key); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				pcolor.PrintFatal(prefix, serveErr.Error())
				return
			}
		}

		//优雅关闭
		pcolor.PrintSucc(prefix, "server exited!")
	}()

	pcolor.PrintSucc(prefix, "listening %s\n", server.Addr)
}

// CORS 中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// 1. 允许所有的 Origin
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// 2. 允许的所有方法
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		// 3. 允许的所有 Header
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Content-Sign, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Expose-Headers", "*")

		w.Header().Set("Access-Control-Max-Age", "3600")

		// 如果是预检请求 (OPTIONS)，直接返回 200，不再执行后续逻辑
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// 继续处理实际请求
		next.ServeHTTP(w, r)
	})
}

func routeHandle(w http.ResponseWriter, r *http.Request) {
	var err error
	var code int
	var userId int64
	var req, res []byte
	var userAgent string

	requestPath := r.URL.Path
	requestRawPath := requestPath

	if r.URL.RawQuery != "" {
		requestRawPath += "?" + r.URL.RawQuery
	}

	defer func() {
		_ = r.Body.Close()
		var errStr string
		if err != nil {
			errStr = err.Error()
			pcolor.PrintErr(prefix, "%+v", err)
			if code == 0 {
				code = http.StatusBadRequest
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(errStr))
		}

		if configLog == "" {
			return
		}
		ip := clientIP(r)
		go logCollector(userAgent, ip, r.RequestURI, userId, req, res, errStr)
	}()

	if userAgent, err = handleUserAgent(r); err != nil {
		code = http.StatusForbidden
		return
	}

	domain, uriPath, err := requestPathParts(requestPath)
	if err != nil {
		return
	}

	serverAddr, err := route(domain)
	if err != nil {
		code = http.StatusNotFound
		return
	}

	if req, err = handleBody(r); err != nil {
		code = http.StatusServiceUnavailable
		return
	}

	ak, err := handleAuth(r, req, requestRawPath)
	if err != nil {
		code = http.StatusUnauthorized
		return
	}

	userId, session, err := auth.ID(ak)
	if err != nil {
		code = http.StatusUnauthorized
		return
	}

	if err = handleRateLimit(requestRawPath, userId); err != nil {
		code = http.StatusTooManyRequests
		return
	}

	if err = handleReplay(r, userId); err != nil {
		code = http.StatusConflict
		return
	}

	if err = handleVerification(userId, session, requestPath); err != nil {
		code = http.StatusUnauthorized
		return
	}

	if res, err = handleRelay(serverAddr, uriPath, userId, req); err != nil {
		code = http.StatusBadGateway
		return
	}

	if err = handleResponse(w, res, requestRawPath, ak); err != nil {
		code = http.StatusUnauthorized
		return
	}
}

func handleUserAgent(r *http.Request) (string, error) {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return "", errors.New("user agent empty")
	}
	if configUserAgent == "" {
		return userAgent, nil
	}
	if !strings.HasPrefix(userAgent, configUserAgent) {
		return "", errors.Errorf("user agent illegal: %s", userAgent)
	}
	return userAgent, nil
}

func handleBody(r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 10<<20)
	return io.ReadAll(r.Body)
}

func handleAuth(r *http.Request, req []byte, requestRawPath string) (string, error) {
	sign := r.Header.Get("content-sign")
	if sign == "" {
		return "", errors.New("missing data signature")
	}
	return auth.Check(sign, out, req, requestRawPath)
}

func handleRateLimit(path string, userId int64) error {
	key := kv.HashKey(fmt.Sprintf("%s_%d", path, userId))
	exists, err := kv.Exists(key, 400)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("rate limit exceeded, please try again later")
	}
	return nil
}

func handleReplay(r *http.Request, id int64) error {
	sign := r.Header.Get("content-sign")
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

func handleVerification(uid, session int64, path string) error {
	if configAccess == "" { //没有权限
		return nil
	}
	result, err := client.Do[bool](uid, configAccess, http.MethodPost, struct {
		Session int64
		Path    string
	}{session, path}, client.GOB, client.GOB)
	if err != nil {
		return err
	}
	if !result {
		return errors.New("verification failed")
	}
	return nil
}

func handleRelay(serverAddr, uriPath string, userId int64, req []byte) ([]byte, error) {
	res, err := client.Do[[]byte](1, serverAddr+"/"+uriPath, http.MethodPost, req, client.BYTES, client.BYTES, map[string]any{
		"user-id": userId,
	})
	return res, err
}

func handleResponse(w http.ResponseWriter, res []byte, requestRawPath, ak string) error {
	sign, err := auth.Sign(res, ak, requestRawPath)
	if err != nil {
		return err
	}
	w.Header().Set("content-sign", sign)
	w.Header().Set("Content-Length", strconv.Itoa(len(res)))
	_, _ = w.Write(res)
	return nil
}

func Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		pcolor.PrintError(prefix, err)
	}
	kv.Close()
}

func clientIP(r *http.Request) string {
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func sslPem() (string, string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	dir := filepath.Dir(exePath)
	sslPath := filepath.Join(dir, "ssl")
	if _, err = os.Stat(sslPath); err != nil {
		dir, err = os.Getwd()
		if err != nil {
			return "", "", errors.WithStack(err)
		}
		sslPath = filepath.Join(dir, "ssl")
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
	if len(entries) < 2 {
		return "", "", nil
	}
	var pemPath, keyPath string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileName := entry.Name()
		ext := strings.ToLower(filepath.Ext(fileName))
		if ext == ".pem" && pemPath == "" {
			pemPath = filepath.Join(sslPath, fileName)
		}
		if ext == ".key" && keyPath == "" {
			keyPath = filepath.Join(sslPath, fileName)
		}
		if pemPath != "" && keyPath != "" {
			break
		}
	}
	return pemPath, keyPath, nil
}

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

func route(key string) (string, error) {
	if value, ok := configServer[key]; ok {
		if len(value) == 0 {
			return "", errors.New("route is empty")
		}
		return value, nil
	}
	return "", errors.Errorf("no found route : %s", key)
}

type data struct {
	UserAgent string
	Ip        string
	Uri       string
	Uid       int64
	Request   []byte
	Response  []byte
	Error     string
}

func logCollector(userAgent string, realIP string, uri string, uid int64, req []byte, res []byte, errStr string) {
	d := data{
		UserAgent: userAgent,
		Ip:        realIP,
		Uri:       uri,
		Uid:       uid,
		Request:   req,
		Response:  res,
		Error:     errStr,
	}
	if _, err := client.Do[any](1, configLog, http.MethodPost, d, client.GOB, client.NIL); err != nil {
		pcolor.PrintErr(prefix, "%+v", err)
	}
}
