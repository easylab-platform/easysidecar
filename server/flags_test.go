package server

import "testing"

func TestHostPort(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"http://mihomo.develop.svc:7890": "mihomo.develop.svc:7890",
		"https://proxy.internal:3128":    "proxy.internal:3128",
		"http://proxy.internal:3128/":    "proxy.internal:3128",
		"proxy.internal:3128":            "proxy.internal:3128",
	}
	for in, want := range cases {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" 1000, 2000 ,,3000 ")
	want := []string{"1000", "2000", "3000"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(splitCSV("")) != 0 {
		t.Fatal("empty must yield no entries")
	}
}
