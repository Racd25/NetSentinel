package enrichment

import "testing"

func TestParseBanner(t *testing.T) {
	tests := []struct {
		banner  string
		product string
		version string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "openssh", "8.9p1"},
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"Apache/2.4.49 (Ubuntu)", "apache", "2.4.49"},
		{"dnsmasq-2.86", "dnsmasq", "2.86"},
		{"algo desconocido", "", ""},
	}

	for _, tt := range tests {
		p, v := ParseBanner(tt.banner)
		if p != tt.product || v != tt.version {
			t.Errorf("ParseBanner(%q) = (%q,%q), want (%q,%q)", tt.banner, p, v, tt.product, tt.version)
		}
	}
}
