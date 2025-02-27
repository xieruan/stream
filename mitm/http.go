package mitm

import (
	"bytes"
	"log"
	"net"
	"strings"

	"github.com/aiocloud/stream/api"
	"github.com/aiocloud/stream/dns"
)

func beginHTTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	s := GetListenPort(ln.Addr().String())
	log.Printf("[HTTP][%s] Started", s)

	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}

		go handleHTTP(client, s)
	}
}

func handleHTTP(client net.Conn, s string) {
	defer client.Close()

	// 获取客户端地址
	clientAddr := client.RemoteAddr().String()

	// [新增] 第一步：立即阻断本地回环客户端
	{
		// 分离 IP 和端口
		clientIP, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			// 处理无端口的情况（理论上不会发生，但安全处理）
			clientIP = clientAddr
		}

		// 检查是否为回环 IP
		if ip := net.ParseIP(clientIP); ip != nil && ip.IsLoopback() {
			log.Printf("[HTTP][%s][%s] Block loopback client", s, clientAddr)
			return
		}

		// 检查地址字符串包含 localhost
		if strings.Contains(strings.ToLower(clientAddr), "localhost") {
			log.Printf("[HTTP][%s][%s] Block localhost client", s, clientAddr)
			return
		}
	}

	// 原有 API 检查
	if !api.Fetch(clientAddr) {
		log.Printf("[HTTP][%s][%s] IP Not Allow", s, clientAddr)
		return
	}

	// 读取 HTTP 请求
	data := make([]byte, 1400)
	size, err := client.Read(data)
	if err != nil {
		return
	}
	data = data[:size]

	// 解析 HTTP Headers
	offset := bytes.Index(data, []byte{0x0d, 0x0a, 0x0d, 0x0a})
	if offset == -1 {
		return
	}

	list := make(map[string]string)
	{
		hdr := bytes.Split(data[:offset], []byte{0x0d, 0x0a})
		for i := 0; i < len(hdr); i++ {
			if i == 0 {
				continue
			}

			SPL := strings.SplitN(string(hdr[i]), ":", 2)
			if len(SPL) < 2 {
				continue
			}

			list[strings.ToUpper(strings.TrimSpace(SPL[0]))] = strings.TrimSpace(SPL[1])
		}
	}

	// 必须包含 Host 头
	hostPort, ok := list["HOST"]
	if !ok {
		return
	}

	// [新增] 第二步：阻断访问本地服务的请求
	{
		// 解析 Host
		host, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			host = hostPort // 处理不带端口的情况
		}

		// 统一小写处理
		host = strings.ToLower(host)

		// 阻断条件
		switch {
		case host == "localhost":
			log.Printf("[HTTP][%s][%s] Block localhost host", s, clientAddr)
			return
		case host == "127.0.0.1", host == "::1":
			log.Printf("[HTTP][%s][%s] Block loopback host", s, clientAddr)
			return
		default:
			// 通用回环地址检测
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				log.Printf("[HTTP][%s][%s] Block loopback IP host", s, clientAddr)
				return
			}
		}
	}

	// [原有] 第三步：阻断自连请求
	{
		clientIP, _, _ := net.SplitHostPort(clientAddr) // 前面已验证过格式
		host, _, _ := net.SplitHostPort(hostPort)      // 前面已验证过格式
		if host == clientIP {
			log.Printf("[HTTP][%s][%s] Block self connection", s, clientAddr)
			return
		}
	}

	// 记录合法请求
	log.Printf("[HTTP][%s] %s <-> %s", s, clientAddr, hostPort)

	// 建立远程连接
	remote, err := dns.Dial("tcp", net.JoinHostPort(hostPort, s))
	if err != nil {
		return
	}
	defer remote.Close()

	// 转发数据
	if _, err := remote.Write(data); err != nil {
		return
	}
	data = nil // 释放内存

	// 双向转发
	CopyBuffer(client, remote)
}
