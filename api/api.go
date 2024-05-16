package api

import (
	"log"
	"net"
	"net/http"
	"sync"
)

var (
	Secret string

	list  = make([]*net.IPNet, 0)
	mutex sync.RWMutex
)

func ParseIP(s string) net.IP {
	if addr, _, err := net.SplitHostPort(s); err == nil {
		s = addr
	}

	return net.ParseIP(s)
}

func ParseCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		_, cidr, err = net.ParseCIDR(s + "/32")
		if err != nil {
			return nil
		}
	}

	return cidr
}
func List() []*net.IPNet {
	mutex.RLock()
	defer mutex.RUnlock()

	cidrs := make([]*net.IPNet, len(list))
	copy(cidrs, list)
	return cidrs
}
func Delete(addr string) bool {
	ip := ParseIP(addr)
	found := false

	mutex.Lock()
	defer mutex.Unlock()

	for i := 0; i < len(list); i++ {
		if list[i].Contains(ip) {
			// Remove the CIDR at index i by swapping with the last element
			list[i] = list[len(list)-1]
			list = list[:len(list)-1]
			found = true
			break
		}
	}

	return found
}

func Listen(addr string) {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/aio", handleCreate)
		mux.HandleFunc("/purge", handlePurge)
		mux.HandleFunc("/list", handleList)
		mux.HandleFunc("/delete", handleDelete)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		})

		log.Fatalf("[API] %v", http.ListenAndServe(addr, mux))
	}()
}

func Fetch(s string) bool {
	mutex.RLock()
	defer mutex.RUnlock()

	ip := ParseIP(s)

	// 如果 IP 是 0.0.0.0，直接返回 true
	if ip.Equal(net.IPv4(0, 0, 0, 0)) {
		return true
	}

	for i := 0; i < len(list); i++ {
		if list[i].Contains(ip) {
			return true
		}
	}

	return false
}


func Create(s string) bool {
	if Fetch(s) {
		return true
	}

	cidr := ParseCIDR(s)
	if cidr == nil {
		return false
	}

	mutex.Lock()
	defer mutex.Unlock()

	list = append(list, cidr)
	return true
}

func Purge() {
	mutex.Lock()
	defer mutex.Unlock()

	list = make([]*net.IPNet, 0)
}
