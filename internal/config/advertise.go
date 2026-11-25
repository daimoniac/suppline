package config

import (
	"fmt"
	"net"
	"os"
)

// DefaultAdvertiseAddress returns http://<ip>:<port> for the first
// non-loopback IPv4 address of this host, falling back to the hostname.
func DefaultAdvertiseAddress(port int) string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return fmt.Sprintf("http://%s:%d", ip4, port)
			}
		}
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}
