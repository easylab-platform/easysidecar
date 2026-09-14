package main

import (
	"encoding/binary"
	"net"
)

// firstMatch returns the first match pattern of a decision for logging
// ("" when the default action applied).
func firstMatch(dec Decision) string {
	if dec.Rule == nil || len(dec.Rule.Match) == 0 {
		return ""
	}
	return dec.Rule.Match[0]
}

// resetConn aborts a connection with RST instead of a graceful FIN.
func resetConn(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

// buildNXDOMAIN rewrites a query into a response with RCODE=3 and no records.
func buildNXDOMAIN(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binaryFlags(query)
	flags |= 0x8000 // QR=1
	flags |= 0x0003 // RCODE=3 NXDOMAIN
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	return resp
}
