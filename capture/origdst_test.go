package capture

import (
	"net"
	"testing"
)

// TestParseSockaddrIPv4 pins the IPv4 layout: family (host order) | port
// (network order) | addr | zero padding.
func TestParseSockaddrIPv4(t *testing.T) {
	b := []byte{
		0x02, 0x00, // AF_INET, little-endian
		0x01, 0xbb, // port 443, big-endian
		0x0a, 0x00, 0x00, 0x05, // 10.0.0.5
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	ip, port, err := parseSockaddr(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.5")) || port != 443 {
		t.Fatalf("got %s:%d", ip, port)
	}
}

// TestParseSockaddrIPv6 pins the IPv6 layout: family | port | flowinfo |
// 16-byte address.
func TestParseSockaddrIPv6(t *testing.T) {
	addr := net.ParseIP("2001:db8::1").To16()
	b := make([]byte, 28)
	b[0], b[1] = 0x0a, 0x00 // AF_INET6
	b[2], b[3] = 0x00, 0x50 // port 80
	copy(b[8:24], addr)
	ip, port, err := parseSockaddr(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::1")) || port != 80 {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestParseSockaddrShort(t *testing.T) {
	if _, _, err := parseSockaddr([]byte{0x02, 0x00, 0x00}); err == nil {
		t.Fatal("short buffer must error")
	}
}
