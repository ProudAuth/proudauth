// Package ids generates opaque, prefixed, immutable identifiers (DOM-001).
package ids

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Prefixes used for externally visible identifiers. They aid debugging and make
// accidental cross-type use visible; they carry no authority.
const (
	Realm          = "rlm"
	Organization   = "org"
	Domain         = "dom"
	User           = "usr"
	Identifier     = "idf"
	Credential     = "crd"
	RecoveryCode   = "rcv"
	WebAuthn       = "wan"
	Membership     = "mem"
	Group          = "grp"
	GroupMember    = "gmb"
	Project        = "prj"
	ProjectGrant   = "pgr"
	Client         = "cli"
	Redirect       = "rdr"
	Origin         = "ori"
	ClientCred     = "ccr"
	ClientGrant    = "cgr"
	Resource       = "res"
	Scope          = "scp"
	ServicePrinc   = "svc"
	IdentityProv   = "idp"
	ExternalIdent  = "ext"
	Transaction    = "atx"
	Challenge      = "chl"
	Session        = "ses"
	ClientSession  = "csn"
	Consent        = "cns"
	Grant          = "gnt"
	AuthCode       = "acd"
	RefreshFamily  = "rff"
	RefreshToken   = "rft"
	AccessToken    = "tok"
	Revocation     = "rvk"
	DeviceCode     = "dvc"
	PAR            = "par"
	Permission     = "prm"
	Role           = "rol"
	Assignment     = "ras"
	Policy         = "pol"
	PolicyVersion  = "plv"
	Relationship   = "rel"
	Invitation     = "inv"
	InviteBatch    = "ivb"
	JoinRequest    = "jrq"
	ImpRequest     = "imq"
	ImpGrant       = "imp"
	ImpHandoff     = "imh"
	Automation     = "akc"
	AuditEvent     = "evt"
	AuditBatch     = "aub"
	Outbox         = "obx"
	Template       = "tpl"
	Notification   = "ntf"
	Webhook        = "whk"
	Delivery       = "dlv"
	LogoutDelivery = "lgd"
	Job            = "job"
	DownloadToken  = "dlt"
	Idempotency    = "idm"
	Tombstone      = "tmb"
	AssistedRecov  = "arq"
	RegApproval    = "rap"
	AccountMerge   = "amg"
	Connector      = "con"
	Terms          = "trm"
	Config         = "cfg"
	Request        = "req"
	Decision       = "dec"
	Device         = "rmd"
	JoinReq        = "jrq"
	PasswordHist   = "pwh"
	Mailbox        = "mbx"
)

// New returns a new identifier such as "usr_01JEXAMPLE...".
func New(prefix string) string {
	id := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
	return prefix + "_" + strings.ToLower(id.String())
}

// HasPrefix reports whether id was generated with the given prefix.
func HasPrefix(id, prefix string) bool {
	return strings.HasPrefix(id, prefix+"_") && len(id) == len(prefix)+27
}

// Valid reports whether id looks like a well-formed identifier of any known shape.
// It is a cheap syntactic filter applied before database lookups.
func Valid(id string) bool {
	i := strings.IndexByte(id, '_')
	if i < 2 || i > 4 || len(id) != i+27 {
		return false
	}
	for _, c := range id[i+1:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}
