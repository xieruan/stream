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

	// [阻断1] 检查客户端是否为回环地址
	{
		clientIPStr, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			clientIPStr = clientAddr // 降级处理
		}

		// 转换为 IP 对象检查
		if clientIP := net.ParseIP(clientIPStr); clientIP != nil && clientIP.IsLoopback() {
			log.Printf("[HTTP][%s][%s] Block loopback client", s, clientAddr)
			return
		}

		// 额外检查 localhost 字符串
		if strings.Contains(strings.ToLower(clientAddr), "localhost") {
			log.Printf("[HTTP][%s][%s] Block localhost client", s, clientAddr)
			return
		}
	}

	// [原有] API 白名单检查
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

			key := strings.ToUpper(strings.TrimSpace(SPL[0]))
			val := strings.TrimSpace(SPL[1])
			list[key] = val
		}
	}

	// 必须包含 Host 头
	hostPort, ok := list["HOST"]
	if !ok {
		return
	}

	// [阻断2] 检查目标是否为本地服务
	{
		hostStr, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			hostStr = hostPort // 处理不带端口的情况
		}

		// 尝试解析为 IP
		if hostIP := net.ParseIP(hostStr); hostIP != nil {
			if hostIP.IsLoopback() {
				log.Printf("[HTTP][%s][%s] Block loopback host: %s", s, clientAddr, hostPort)
				return
			}
		} else {
			// 如果是域名，检查是否解析为回环地址
			if ips, err := net.LookupIP(hostStr); err == nil {
				for _, ip := range ips {
					if ip.IsLoopback() {
						log.Printf("[HTTP][%s][%s] Block domain resolve to loopback: %s", s, clientAddr, hostStr)
						return
					}
				}
			}
		}
	}

	// [阻断3] 精确自连检查（IP 级别）
	{
		// 解析客户端 IP
		clientIPStr, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			clientIPStr = clientAddr
		}
		clientIP := net.ParseIP(clientIPStr)
		if clientIP == nil {
			log.Printf("[HTTP][%s][%s] Invalid client IP: %s", s, clientAddr, clientIPStr)
			return
		}

		// 解析目标 Host
		hostStr, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			hostStr = hostPort
		}
		hostIP := net.ParseIP(hostStr)
		if hostIP == nil {
			// 如果 Host 是域名，进行 DNS 解析
			if ips, err := net.LookupIP(hostStr); err == nil && len(ips) > 0 {
				hostIP = ips[0] // 取第一个 A 记录
			} else {
				return
			}
		}

		// 比较 IP 地址
		if hostIP.Equal(clientIP) {
			log.Printf("[HTTP][%s][%s] Block self connection to %s", s, clientAddr, hostPort)
			return
		}
	}

	// 记录合法连接
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
