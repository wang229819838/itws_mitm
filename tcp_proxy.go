package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"socks5_mitm/my_aes"
	"strings"
	"sync"
	"time"

	"socks5_mitm/pkg/shadowsocks2/shadowaead"

	_ "github.com/go-sql-driver/mysql"

	"github.com/spf13/pflag"
)

const (
	dbDSN = "itws:Wang@229819838@tcp(124.70.33.51:3306)/socks5_mitm"
)

var port = pflag.Uint16P("port", "p", 10000, "proxy port")
var ca_crt = pflag.StringP("crtPath", "c", "./ca/itws.online_bundle.crt", "证书文件路径")
var ca_key = pflag.StringP("keyPath", "k", "./ca/itws.online.key", "证书私钥路径")

func main() {
	pflag.Parse()
	db, err := sql.Open("mysql", dbDSN)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		return
	}
	defer db.Close()

	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(*ca_crt, *ca_key)
	if err != nil {
		fmt.Printf("Failed to load server certificate and key: %v\n", err)
		return
	}

	// Create a TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// 使用普通的TCP监听器
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Printf("Failed to listen on port %d: %v\n", *port, err)
		return
	}
	defer listener.Close()
	fmt.Printf("Proxy server listening on :%d\n", *port)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		go handleClient(clientConn, db, tlsConfig)
	}
}

func handleClient(clientConn net.Conn, db *sql.DB, tlsConfig *tls.Config) {
	defer clientConn.Close()

	// 读取连接的前四个字节来判断连接类型
	buf := make([]byte, 4)
	_, err := io.ReadFull(clientConn, buf)
	if err != nil {
		fmt.Printf("Failed to read from client: %v\n", err)
		return
	}

	// 使用MultiReader将读取的字节放回连接
	connReader := io.MultiReader(bytes.NewReader(buf), clientConn)

	// 判断连接类型并处理
	if buf[0] >= 20 && buf[0] <= 22 && buf[1] == 3 {
		// TLS连接
		handleTLSClient(connReader, clientConn, db, tlsConfig)
	} else {
		// HTTP连接
		handleHTTPClient(connReader, clientConn, db)
	}
}
func handleTLSClient(connReader io.Reader, clientConn net.Conn, db *sql.DB, tlsConfig *tls.Config) {
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// 将之前读取的字节放回TLS连接
	tlsConnReader := io.MultiReader(connReader, tlsConn)

	// 执行TLS握手
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("TLS handshake failed: %v\n", err)
		return
	}

	// 处理TLS连接
	handleHTTPConnection(tlsConnReader, tlsConn, db, true)
}

func handleHTTPClient(connReader io.Reader, clientConn net.Conn, db *sql.DB) {
	defer clientConn.Close()

	// 处理HTTP连接
	handleHTTPConnection(connReader, clientConn, db, false)
}
func handleHTTPConnection(connReader io.Reader, clientConn net.Conn, db *sql.DB, isTLS bool) {
	// 使用bufio.NewReader包装connReader以便可以按行读取
	bufferedReader := bufio.NewReader(connReader)

	// 读取加密的数据
	encryptedData, err := ioutil.ReadAll(bufferedReader)
	if err != nil {
		fmt.Printf("Failed to read encrypted data: %v\n", err)
		return
	}

	// 使用解密后的数据创建一个新的reader
	decryptedReader := bufio.NewReader(bytes.NewReader(encryptedData))

	// 读取并解析HTTP请求
	req, err := http.ReadRequest(decryptedReader)
	if err != nil {
		fmt.Printf("Failed to read HTTP request: %v\n", err)
		return
	}
	// 验证代理授权
	if !authenticateRequest(req, db) {
		fmt.Println("Authentication failed")
		clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		time.Sleep(time.Second * 15)
		return
	}
	// 处理CONNECT方法
	if req.Method == http.MethodConnect {
		handleConnectMethod(req, clientConn, db)
		return
	}
	// 处理普通HTTP请求
	handleHTTPMethod(req, clientConn, db)
}

func authenticateRequest(req *http.Request, db *sql.DB) bool {
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}
	fmt.Println("authHeader ", authHeader)
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		return false
	}

	username := pair[0]
	password := pair[1]

	// Query the database to validate the username and password
	var dbPassword string
	err = db.QueryRow("SELECT password FROM tb_socks_auth WHERE username = ?", username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// Username not found
			return false
		}
		fmt.Printf("Database query failed: %v\n", err)
		return false
	}

	// Here you should compare the provided password with the stored password
	// You might need to hash the provided password if the stored password is hashed
	return password == dbPassword
}

func handleConnectMethod(req *http.Request, clientConn net.Conn, db *sql.DB) {
	// 连接到目标服务器
	targetAddress := req.URL.Host
	if !strings.Contains(targetAddress, ":") {
		targetAddress = targetAddress + ":443"
	}
	serverConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		fmt.Printf("Failed to connect to server: %v\n", err)
		return
	}
	defer serverConn.Close()

	// 发送连接建立的响应
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// 转发数据
	transferData(clientConn, serverConn)
}

func handleHTTPMethod(req *http.Request, clientConn net.Conn, db *sql.DB) {
	// 连接到目标服务器
	targetAddress := req.URL.Host
	if !strings.Contains(targetAddress, ":") {
		targetAddress = targetAddress + ":80"
	}
	serverConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		fmt.Printf("Failed to connect to server: %v\n", err)
		return
	}
	defer serverConn.Close()

	// 转发HTTP请求
	err = req.Write(serverConn)
	if err != nil {
		fmt.Printf("Failed to forward HTTP request: %v\n", err)
		return
	}

	// 转发数据
	transferData(clientConn, serverConn)
}

func transferData(src, dest net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer src.Close()
		defer dest.Close()
		io.Copy(&loggingWriter{w: dest, tag: "目标服务器与代理服务器"}, &loggingReader{r: src, tag: "客户端与代理服务器"})
	}()
	go func() {
		defer wg.Done()
		defer src.Close()
		defer dest.Close()
		// io.Copy(&loggingWriter{w: src, tag: "客户端与代理服务器"}, &loggingReader{r: dest, tag: "目标服务器与代理服务器"})
		buf := make([]byte, 4096)
		// key := my_aes.EVP_BytesToKey("123456", 16) // 你的密钥
		// 解密数据
		_, c, err := my_aes.EVP_BytesToKey("123456", 16)
		if err != nil {
			fmt.Printf("EVP_BytesToKey: %v\n", err)
			return
		}
		// decryptedData, err := shadowaead.Unpack(encryptedData[c.SaltSize():], encryptedData, c)

		for {
			n, err := src.Read(buf)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("Read error: %v\n", err)
				}
				break
			}

			plaintext, err := shadowaead.Unpack(buf[c.SaltSize():], buf[:n], c)
			// 解密数据
			// plaintext, err := my_aes.DecryptAESGCM(key, buf[:n])
			if err != nil {
				fmt.Printf("Decrypt error: %v\n", err)
				break
			}

			// 将解密后的数据写入目的地
			if _, err := dest.Write(plaintext); err != nil {
				fmt.Printf("Write error: %v\n", err)
				break
			}
		}
	}()
	wg.Wait()
}

type loggingWriter struct {
	w   io.Writer
	tag string
}

func (lw *loggingWriter) Write(p []byte) (n int, err error) {
	n, err = lw.w.Write(p)
	if err == nil && n > 0 {
		fmt.Printf("tag[%s]:Transferred %d\n", lw.tag, n)
		// fmt.Printf("Transferred %d bytes: %s\n", n, p[:n])
	}
	return n, err
}

type loggingReader struct {
	r   io.Reader
	tag string
}

func (lr *loggingReader) Read(p []byte) (n int, err error) {
	n, err = lr.r.Read(p)
	if err == nil && n > 0 {
		fmt.Printf("tag[%s]:Received %d\n", lr.tag, n)
	}
	return n, err
}
