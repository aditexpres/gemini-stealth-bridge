package cookies

import (
	"strings"
	"testing"
)

func TestIsolatedLoginArgsDisableDBSC(t *testing.T) {
	args := isolatedLoginArgs("/tmp/gsb-isolated-profile", 9222)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--user-data-dir=/tmp/gsb-isolated-profile",
		"--remote-debugging-port=9222",
		"--disable-features=DeviceBoundSessionCredentials",
		"https://gemini.google.com/app",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("isolated login args missing %q: %v", want, args)
		}
	}
}

func TestExtractGoogleCookiesFromCDPDomainPrecedence(t *testing.T) {
	hdr, ok := extractGoogleCookiesFromCDP([]cdpCookie{
		{Name: "SIDCC", Value: "sub-sidcc", Domain: "accounts.google.com"},
		{Name: "SAPISID", Value: "root-sapisid", Domain: ".google.com"},
		{Name: "__Secure-1PSID", Value: "root-1psid", Domain: ".google.com"},
		{Name: "__Secure-1PSIDTS", Value: "sub-1psidts", Domain: "accounts.google.com"},
		{Name: "__Secure-1PSIDTS", Value: "root-1psidts", Domain: ".google.com"},
		{Name: "SIDCC", Value: "root-sidcc", Domain: ".google.com"},
	})
	if !ok {
		t.Fatal("expected cookies to be accepted")
	}
	parsed := ParseHeader(hdr)
	if parsed["SIDCC"] != "root-sidcc" {
		t.Fatalf("expected .google.com SIDCC, got %q", parsed["SIDCC"])
	}
	if parsed["__Secure-1PSIDTS"] != "root-1psidts" {
		t.Fatalf("expected .google.com __Secure-1PSIDTS, got %q", parsed["__Secure-1PSIDTS"])
	}
}
