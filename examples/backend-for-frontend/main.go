// Command backend-for-frontend runs the example BFF against a ProudAuth realm.
//
//	PROUDAUTH_ISSUER=https://id.example.com/realms/main CLIENT_ID=web-bff CLIENT_SECRET=... \
//	REDIRECT_URI=https://app.example.com/callback ORDERS_API=https://orders.example.com go run ./examples/backend-for-frontend
package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/proudauth/proudauth-sdk-go/oidcclient"
	"github.com/proudauth/proudauth/examples/backend-for-frontend/bff"
)

func main() {
	c, err := oidcclient.New(oidcclient.Config{Issuer: os.Getenv("PROUDAUTH_ISSUER"), ClientID: os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"), RedirectURI: os.Getenv("REDIRECT_URI"),
		Scopes: strings.Fields(envOr("SCOPES", "openid orders:read")), Resource: os.Getenv("RESOURCE")})
	if err != nil {
		log.Fatal(err)
	}
	b := bff.New(c, os.Getenv("ORDERS_API"), os.Getenv("APP_ORIGIN"), os.Getenv("POST_LOGOUT_REDIRECT"))
	log.Fatal(http.ListenAndServe(envOr("LISTEN", ":3000"), b.Handler()))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
