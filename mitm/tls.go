package mitm

import (
	"log"
	"net"
	"strings"

	"github.com/aiocloud/stream/api"
	"github.com/aiocloud/stream/dns"
)

// 启动TLS监听服务
func beginTLS(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	port := getListenPort(ln.Addr().String())
	log.Printf("[TLS][%s] Service started", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleTLSConnection(conn, port)
	}
}

// 处理单个TLS连接
func handleTLSConnection(client net.Conn, port string) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()

	// 第一阶段：客户端验证
	clientIP, ok := validateClient(clientAddr, port)
	if !ok {
		return
	}

	// 解析TLS Client Hello
	sni, ok := parseTLSSNI(client, port, clientAddr)
	if !ok {
		return
	}

	// 第二阶段：目标验证
	targetHost := extractTargetHost(sni)
	if shouldBlockTarget(targetHost, clientIP, port, clientAddr) {
		return
	}

	// 建立代理连接
	log.Printf("[TLS][%s] %s -> %s", port, clientAddr, sni)
	proxyConnection(client, sni, port, clientAddr)
}

// 客户端验证逻辑
func validateClient(addr, port string) (net.IP, bool) {
	// 解析客户端IP
	ipStr, _, err := net.SplitHostPort(addr)
	if err != nil {
		ipStr = addr
	}

	// 检查IP格式
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("[TLS][%s][%s] Invalid client IP format", port, addr)
		return nil, false
	}

	// 阻断回环地址
	if ip.IsLoopback() || ip.IsUnspecified() {
		log.Printf("[TLS][%s][%s] Block loopback client", port, addr)
		return nil, false
	}

	// API授权检查
	if !api.Fetch(ipStr) {
		log.Printf("[TLS][%s][%s] IP not allowed", port, addr)
		return nil, false
	}

	return ip, true
}

// 解析TLS SNI
func parseTLSSNI(client net.Conn, port, clientAddr string) (string, bool) {
	buf := make([]byte, 1400)
	n, err := client.Read(buf)
	if err != nil || n <= 44 {
		return "", false
	}

	// 检查TLS记录类型
	if buf[0] != 0x16 {
		return "", false
	}

	// 解析SNI字段
	sni := parseSNI(buf[:n])
	if sni == "" {
		log.Printf("[TLS][%s][%s] No SNI provided", port, clientAddr)
	}
	return sni, sni != ""
}

// 目标验证逻辑
func shouldBlockTarget(host string, clientIP net.IP, port, clientAddr string) bool {
	// 阻断IP地址格式
	if isIPAddress(host) {
		log.Printf("[TLS][%s][%s] Block IP-based SNI: %s", port, clientAddr, host)
		return true
	}

	// 特殊关键字阻断
	if strings.EqualFold(host, "localhost") {
		log.Printf("[TLS][%s][%s] Block localhost", port, clientAddr)
		return true
	}

	// DNS解析检查
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Printf("[TLS][%s][%s] DNS lookup failed: %s", port, clientAddr, host)
		return true
	}

	// IP匹配检查
	for _, ip := range ips {
		if normalizeIP(ip).Equal(normalizeIP(clientIP)) {
			log.Printf("[TLS][%s][%s] Block self-connection: %s", 
				port, clientAddr, ip)
			return true
		}
	}
	return false
}

// 工具函数集
func getListenPort(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}

func isIPAddress(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
		return net.ParseIP(h) != nil
	}
	return net.ParseIP(host) != nil
}

func extractTargetHost(sni string) string {
	host, _, err := net.SplitHostPort(sni)
	if err != nil {
		return sni
	}
	return host
}

func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func proxyConnection(client net.Conn, target, port, clientAddr string) {
	remote, err := dns.Dial("tcp", net.JoinHostPort(target, port))
	if err != nil {
		log.Printf("[TLS][%s][%s] Connect failed: %v", port, clientAddr, err)
		return
	}
	defer remote.Close()

	// 数据转发逻辑
	go func() {
		defer client.Close()
		_, _ = remote.ReadFrom(client)
	}()

	_, _ = client.ReadFrom(remote)
}

// TLS解析实现
func parseSNI(data []byte) string {
	offset := 5 // 跳过协议版本等字段

	// 基础结构校验
	if len(data) < offset+38 {
		return ""
	}

	// 跳过Random、SessionID等字段
	offset += 32 // Random
	offset += 1  // SessionID长度
	offset += int(data[offset-1])

	// 处理Cipher Suites
	if offset+2 > len(data) {
		return ""
	}
	cipherLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherLen

	// 处理Compression Methods
	if offset >= len(data) {
		return ""
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	// 处理Extensions
	if offset+2 > len(data) {
		return ""
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	endOffset := offset + extensionsLen

	for offset < endOffset && offset+4 <= len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0 { // SNI扩展
			return parseSNIEntry(data[offset : offset+extLen])
		}
		offset += extLen
	}
	return ""
}

func parseSNIEntry(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]

		if nameType != 0 || len(data) < nameLen {
			break
		}

		if nameLen > 0 {
			return string(data[:nameLen])
		}
		data = data[nameLen:]
	}
	return ""
}
