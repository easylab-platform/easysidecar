package relay

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/easylab-platform/easysidecar/capture"
	"github.com/easylab-platform/easysidecar/rule"
)

// TestCaptureMarkedDialContext verifies the capture face hands the transport a
// marked dialer whenever a mark is configured (the self-loop guard), and none
// otherwise.
func TestCaptureMarkedDialContext(t *testing.T) {
	s := &CaptureTCP{Mark: capture.Mark}
	if s.markedDialContext() == nil {
		t.Fatal("marked dial context must be set when Mark != 0")
	}
	if (&CaptureTCP{}).markedDialContext() != nil {
		t.Fatal("no mark means no custom dialer")
	}
}

// TestBuildRewriteProxyCarriesDialer verifies the marked dialer reaches the
// reverse proxy's transport (otherwise the proxy's upstream dials would be
// redirected back into the sidecar).
func TestBuildRewriteProxyCarriesDialer(t *testing.T) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}
	rp := buildRewriteProxy(&rule.Rule{Target: "gw:80", AddPrefix: "/pkgs/npm"},
		"registry.npmjs.org", "https", dial, nil)
	tr, ok := rp.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", rp.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("custom dialer not wired into the transport")
	}
}

// TestBuildRewriteProxyDefaultDialer verifies the spoof face keeps net/http's
// default dialer when none is supplied.
func TestBuildRewriteProxyDefaultDialer(t *testing.T) {
	rp := buildRewriteProxy(&rule.Rule{Target: "gw:80"}, "pypi.org", "https", nil, nil)
	tr := rp.Transport.(*http.Transport)
	if tr.DialContext != nil {
		t.Fatal("nil dialer must leave the transport default in place")
	}
}
