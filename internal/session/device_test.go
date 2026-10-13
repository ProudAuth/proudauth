package session

import "testing"

func TestDeviceLabel(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15":    "Safari on macOS",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0": "Edge on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0":                                                "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36":              "Chrome on Android",
		"curl/8.7.1": "curl",
		"":           "",
		"???":        "Unknown device",
	} {
		if got := DeviceLabel(ua); got != want {
			t.Errorf("%q: got %q, want %q", ua, got, want)
		}
	}
}
