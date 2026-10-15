// Command protected-orders-api runs the example strict-online resource server.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/proudauth/proudauth/examples/protected-orders-api/ordersapi"
)

func main() {
	api, err := ordersapi.New(ordersapi.Config{Issuer: os.Getenv("PROUDAUTH_ISSUER"), Audience: os.Getenv("AUDIENCE"),
		ClientID: os.Getenv("CLIENT_ID"), ClientSecret: os.Getenv("CLIENT_SECRET")})
	if err != nil {
		log.Fatal(err) // the support contract must be satisfied at startup (INT-010)
	}
	log.Fatal(http.ListenAndServe(":8081", api.Handler()))
}
