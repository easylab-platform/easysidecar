package relay

import (
	"net"
	"testing"
)

// TestMatchAllow pins the allow-list matching: host, cidr, host:port, cidr:port.
func TestMatchAllow(t *testing.T) {
	allow := []string{"1.1.1.1", "10.0.0.0/8", "8.8.8.8:53", "192.168.0.0/16:123"}
	cases := []struct {
		ip   string
		port int
		want bool
	}{
		{"1.1.1.1", 9999, true}, // host, any port
		{"1.1.1.2", 53, false},  // not listed
		{"10.4.5.6", 123, true}, // cidr, any port
		{"8.8.8.8", 53, true},   // host:port exact
		{"8.8.8.8", 54, false},  // host:port mismatch
		{"192.168.1.9", 123, true},
		{"192.168.1.9", 321, false},
		{"11.0.0.1", 123, false}, // outside cidr
	}
	for _, c := range cases {
		got := matchAllow(allow, net.ParseIP(c.ip), c.port)
		if got != c.want {
			t.Errorf("matchAllow(%s:%d) = %v want %v", c.ip, c.port, got, c.want)
		}
	}
	if matchAllow(nil, net.ParseIP("1.1.1.1"), 53) {
		t.Fatal("empty allow-list must match nothing")
	}
}
