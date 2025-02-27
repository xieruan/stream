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

	if !api.Fetch(client.RemoteAddr().String()) {
		log.Printf("[HTTP][%s][%s] IP Not Allow", s, client.RemoteAddr())
		return
	}

	data := make([]byte, 1400)
	size, err := client.Read(data)
	if err != nil {
		return
	}
	data = data[:size]

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

	if _, ok := list["HOST"]; !ok {
		return
	}

	// 提取 Host 和客户端 IP 进行比较
	hostPort := list["HOST"]
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil { // 处理不带端口的情况
		host = hostPort
	}

	clientAddr := client.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		log.Printf("[HTTP][%s][%s] Invalid client address: %v", s, clientAddr, err)
		return
	}

	// 如果 Host 主机部分和客户端 IP 相同则阻断
	if host == clientIP {
		log.Printf("[HTTP][%s][%s] Block self connection to %s", s, clientAddr, host)
		return
	}

	log.Printf("[HTTP][%s] %s <-> %s", s, clientAddr, list["HOST"])

	remote, err := dns.Dial("tcp", net.JoinHostPort(list["HOST"], s))
	if err != nil {
		return
	}
	defer remote.Close()

	if _, err := remote.Write(data); err != nil {
		return
	}
	data = nil

	CopyBuffer(client, remote)
}
