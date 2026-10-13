package httpapi

import (
	"crypto/x509"
	"net/http"

	"github.com/proudbase/proudauth/internal/certauth"
)

// peerCertificate returns the client certificate of a request and any
// intermediates sent with it (TOK-019, MCH-014, PROV-016): from the TLS
// connection (the mutual-TLS listener asks for one), or, behind a
// TLS-terminating proxy listed in server.trusted_proxies, from
// server.client_cert_header. The header is never read from other peers, so a
// client cannot claim a certificate it does not hold.
func (a *App) peerCertificate(r *http.Request) (*x509.Certificate, []*x509.Certificate) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], r.TLS.PeerCertificates[1:]
	}
	if h := a.D.Cfg.Server.ClientCertHeader; h != "" && a.fromTrustedProxy(r) {
		if c, err := certauth.ParseHeader(r.Header.Get(h)); err == nil {
			return c, nil
		}
	}
	return nil, nil
}
