package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// PARResponse is the RFC 9126 response.
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

const parTTL = 60 * time.Second

// PushAuthorizationRequest stores a validated authorization request submitted by an
// authenticated client and returns a single-use request reference (RFC 9126).
func (s *Service) PushAuthorizationRequest(ctx context.Context, rlm *realm.Realm, c *application.Client, v url.Values) (*PARResponse, *Error) {
	if v.Get("request_uri") != "" {
		return nil, ErrInvalidRequest("request_uri is not allowed in a pushed request")
	}
	req, oe := ParseAuthorize(v)
	if oe != nil {
		return nil, oe
	}
	if req.ClientID != "" && req.ClientID != c.ClientID {
		return nil, ErrInvalidRequest("client_id mismatch")
	}
	req.ClientID = c.ClientID
	req.RequestURI = "pushed"
	if _, oe, _ := s.validateInteractive(ctx, rlm, req); oe != nil {
		return nil, oe
	}
	req.RequestURI = ""
	params, _ := json.Marshal(req)
	ref := secret.PrefixPAR + secret.Token("")
	now := s.d.Now()
	if _, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO pushed_authorization_requests (id, realm_id, client_ref, request_uri_digest, parameters, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, ids.New(ids.PAR), rlm.ID, c.Ref, secret.Digest(ref), params, now.Add(parTTL), now); err != nil {
		return nil, ErrServerError
	}
	return &PARResponse{RequestURI: ref, ExpiresIn: int(parTTL.Seconds())}, nil
}

// consumePAR redeems a pushed request reference for the client presenting it
// (RFC 9126 §4). The client is resolved before the reference is touched, and
// the consuming UPDATE matches the pushing client (client_ref), so a
// request_uri presented with another client's client_id, an unknown one or
// none is refused without spending it: only its own client can use it, once.
// The refusal is the same whether or not the reference exists.
func (s *Service) consumePAR(ctx context.Context, rlm *realm.Realm, clientID, ref string) (AuthorizeRequest, *Error) {
	if clientID == "" {
		return AuthorizeRequest{}, ErrInvalidRequest("client_id is required with request_uri")
	}
	c, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, clientID)
	if err != nil {
		return AuthorizeRequest{}, ErrInvalidRequest("invalid or expired request_uri")
	}
	var params []byte
	err = s.d.DB.Pool.QueryRow(ctx, `UPDATE pushed_authorization_requests SET consumed_at=$3 WHERE realm_id=$1 AND request_uri_digest=$2
		AND client_ref=$4 AND consumed_at IS NULL AND expires_at > $3 RETURNING parameters`, rlm.ID, secret.Digest(ref), s.d.Now(), c.Ref).Scan(&params)
	if err != nil {
		return AuthorizeRequest{}, ErrInvalidRequest("invalid or expired request_uri")
	}
	var req AuthorizeRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return AuthorizeRequest{}, ErrInvalidRequest("invalid request_uri")
	}
	req.RequestURI = ref // marks the request as pushed for RequirePAR clients
	return req, nil
}
