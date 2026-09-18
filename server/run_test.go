package server

import "testing"

func TestWithPort(t *testing.T) {
	cases := map[string]string{
		"10.96.0.10":    "10.96.0.10:53",
		"10.96.0.10:53": "10.96.0.10:53",
		"":              "8.8.8.8:53",
	}
	for in, want := range cases {
		if got := withPort(in, "53"); got != want {
			t.Errorf("withPort(%q) = %q want %q", in, got, want)
		}
	}
}
