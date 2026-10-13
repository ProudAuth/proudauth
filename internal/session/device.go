package session

import "strings"

// DeviceLabel derives a coarse, human-readable description ("Firefox on
// macOS") from a user agent for session lists (SES-013). It is a display hint
// only: user agents are client-controlled and never used for security
// decisions.
func DeviceLabel(ua string) string {
	if ua == "" {
		return ""
	}
	l := strings.ToLower(ua)
	browser := ""
	for _, b := range []struct{ token, name string }{
		{"edg/", "Edge"}, {"opr/", "Opera"}, {"firefox/", "Firefox"}, {"chrome/", "Chrome"}, {"safari/", "Safari"},
		{"curl/", "curl"}, {"go-http-client", "Go client"}, {"okhttp", "Android app"}, {"cfnetwork", "Apple app"},
	} {
		if strings.Contains(l, b.token) {
			browser = b.name
			break
		}
	}
	os := ""
	for _, o := range []struct{ token, name string }{
		{"iphone", "iOS"}, {"ipad", "iPadOS"}, {"android", "Android"}, {"windows", "Windows"}, {"mac os x", "macOS"},
		{"macintosh", "macOS"}, {"cros", "ChromeOS"}, {"linux", "Linux"},
	} {
		if strings.Contains(l, o.token) {
			os = o.name
			break
		}
	}
	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return "Browser on " + os
	}
	return "Unknown device"
}
