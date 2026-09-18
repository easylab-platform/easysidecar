package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/easylab-platform/easysidecar/capture"
	"github.com/easylab-platform/easysidecar/logging"
)

// CaptureUDP is the datagram side of the capture face. TCP interception
// recovers the original destination from the socket (SO_ORIGINAL_DST); UDP has
// no connection, so the destination arrives in an IP_RECVORIGDSTADDR control
// message instead (capture.ParseOrigDst).
//
// Every datagram flow is logged once with its real destination. Allowed flows
// (manual allow-list) are relayed with a per-flow upstream socket; replies are
// written back through the listener, whose source is the DNAT target, so
// conntrack un-DNATs them to the original destination.
//
// Policy:
//   - QUIC/h3 (udp/443) is always dropped: it cannot be MITM'd yet, so letting
//     it through would bypass the proxy.
//   - Mode "reject" drops anything not in the allow-list (logged as udp-block).
//   - Mode "log" relays everything (logged) — observe before enforcing.
type CaptureUDP struct {
	Addr    string
	Allow   []string
	Mode    string // "log" (relay + log) or "reject" (drop non-allowed)
	Mark    int
	Logger  *logging.ConnLogger
	Timeout time.Duration
}

// udpFlow is one client->destination datagram conversation.
type udpFlow struct {
	up    *net.UDPConn
	key   string
	dst   string
	bytes int64
	mu    sync.Mutex
}

// Serve listens until the socket fails.
func (s *CaptureUDP) Serve() error {
	pc, err := net.ListenUDP("udp", mustUDPAddr(s.Addr))
	if err != nil {
		return fmt.Errorf("capture udp listen %s: %w", s.Addr, err)
	}
	if err := capture.EnableOrigDst(pc); err != nil {
		return fmt.Errorf("capture udp origdst %s: %w", s.Addr, err)
	}
	if err := capture.SetMark(pc, s.Mark); err != nil {
		return fmt.Errorf("capture udp mark %s: %w", s.Addr, err)
	}
	s.Logger.Log(logging.ConnLogEntry{Action: "info", Dst: "listening capture-udp " + s.Addr +
		" mode=" + s.mode()})

	flows := map[string]*udpFlow{}
	var mu sync.Mutex
	buf := make([]byte, 64<<10)
	oob := make([]byte, capture.OrigDstOOBSize)
	for {
		n, oobn, _, client, err := pc.ReadMsgUDP(buf, oob)
		if err != nil {
			return err
		}
		dstIP, dstPort, ok := capture.ParseOrigDst(oob[:oobn])
		if !ok {
			la := pc.LocalAddr().(*net.UDPAddr)
			dstIP, dstPort = la.IP, la.Port
		}
		dst := net.JoinHostPort(dstIP.String(), strconv.Itoa(dstPort))

		// h3 can never be intercepted; always drop it.
		if dstPort == 443 {
			s.Logger.Log(logging.ConnLogEntry{Host: dstIP.String(), Dst: dst,
				Action: "h3-block", Bytes: int64(n)})
			continue
		}
		// The nat chain has already applied the allow-list; the face only
		// relays allowed flows. Anything else is audited as blocked (the
		// filter chain dropped it in reject mode; in log mode it is dropped
		// here too, so unlisted destinations never get a working path).
		if !matchAllow(s.Allow, dstIP, dstPort) {
			s.Logger.Log(logging.ConnLogEntry{Host: dstIP.String(), Dst: dst,
				Action: "udp-block", Bytes: int64(n)})
			continue
		}

		key := client.String()
		mu.Lock()
		f := flows[key]
		if f == nil || f.dst != dst {
			if f != nil {
				_ = f.up.Close()
			}
			up, derr := dialUDP(dst, s.Mark, s.idle())
			if derr != nil {
				mu.Unlock()
				s.Logger.Log(logging.ConnLogEntry{Host: dstIP.String(), Dst: dst,
					Action: "udp", Err: derr.Error()})
				continue
			}
			f = &udpFlow{up: up, key: key, dst: dst}
			flows[key] = f
			s.Logger.Log(logging.ConnLogEntry{Host: dstIP.String(), Dst: dst, Action: "udp"})
			go s.readReplies(pc, client, f, &mu, flows)
		}
		_, _ = f.up.Write(buf[:n])
		f.bytes += int64(n)
		mu.Unlock()
	}
}

// readReplies pumps the upstream socket back to the client until it idles out.
func (s *CaptureUDP) readReplies(pc *net.UDPConn, client *net.UDPAddr, f *udpFlow, mu *sync.Mutex, flows map[string]*udpFlow) {
	buf := make([]byte, 64<<10)
	for {
		_ = f.up.SetReadDeadline(time.Now().Add(s.idle()))
		n, err := f.up.Read(buf)
		if err != nil {
			break
		}
		f.mu.Lock()
		f.bytes += int64(n)
		f.mu.Unlock()
		_, _ = pc.WriteToUDP(buf[:n], client)
	}
	mu.Lock()
	if flows[f.key] == f {
		delete(flows, f.key)
	}
	mu.Unlock()
	_ = f.up.Close()
	s.Logger.Log(logging.ConnLogEntry{Host: hostOfAddr(f.dst), Dst: f.dst, Action: "udp-close", Bytes: f.bytes})
}

func (s *CaptureUDP) mode() string {
	if s.Mode == "reject" {
		return "reject"
	}
	return "log"
}

func (s *CaptureUDP) idle() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Second
}

// matchAllow reports whether ip:port matches an allow entry. Entries are
// "host", "cidr", "host:port" or "cidr:port"; a missing port matches any.
func matchAllow(allow []string, ip net.IP, port int) bool {
	for _, ep := range allow {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		host, wantPort := ep, 0
		if h, p, err := net.SplitHostPort(ep); err == nil {
			host = h
			if n, cerr := strconv.Atoi(p); cerr == nil {
				wantPort = n
			}
		}
		if wantPort != 0 && wantPort != port {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(host); err == nil {
			if ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if hIP := net.ParseIP(host); hIP != nil && hIP.Equal(ip) {
			return true
		}
	}
	return false
}

func mustUDPAddr(a string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	return ua
}

func dialUDP(dst string, mark int, timeout time.Duration) (*net.UDPConn, error) {
	ra, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return nil, err
	}
	if mark == 0 {
		return net.DialUDP("udp", nil, ra)
	}
	// SO_MARK so the nat chain's mark RETURN exempts the sidecar's own egress.
	conn, err := capture.MarkedDialer(mark).Dial("udp", dst)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected udp conn type %T", conn)
	}
	return uc, nil
}

func hostOfAddr(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}
