// Command machine-client demonstrates the client-credentials grant (MCH-002): a
// service principal obtains a short-lived, audience-bound token and re-authenticates
// instead of receiving a refresh token (MCH-003).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	issuer := os.Getenv("PROUDAUTH_ISSUER")
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {os.Getenv("RESOURCE")}, "scope": {os.Getenv("SCOPE")}}
	if org := os.Getenv("ORGANIZATION"); org != "" {
		form.Set("organization", org)
	}
	req, _ := http.NewRequest(http.MethodPost, issuer+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(os.Getenv("CLIENT_ID")), url.QueryEscape(os.Getenv("CLIENT_SECRET")))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != 200 {
		log.Fatalf("token request failed: %v", out["error"])
	}
	fmt.Printf("access token expires in %v seconds (scope %q); never log the token itself\n", out["expires_in"], out["scope"])
}
