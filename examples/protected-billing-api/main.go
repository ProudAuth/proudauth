// Command protected-billing-api runs the example offline-verifying resource server.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/proudbase/proudauth-sdk-go/verifier"
	"github.com/proudbase/proudauth/examples/protected-billing-api/billingapi"
)

func main() {
	v, err := verifier.New(verifier.Config{Issuer: os.Getenv("PROUDAUTH_ISSUER"), Audience: os.Getenv("AUDIENCE")})
	if err != nil {
		log.Fatal(err)
	}
	api := &billingapi.API{V: v}
	log.Fatal(http.ListenAndServe(":8082", api.Handler()))
}
