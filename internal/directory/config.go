package directory

import (
	"crypto/x509"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// Connector kinds this module manages. Inbound SCIM connectors
// ('scim_inbound') belong to internal/provisioning.
const (
	KindLDAP     = "ldap"
	KindOutbound = "scim_outbound"
)

// Write modes of a directory connector (PROV-013).
const (
	// ModeReadOnly: the directory owns the mapped attributes, the account
	// lifecycle and the password; local edits of mapped attributes are
	// refused and nothing is written to the directory.
	ModeReadOnly = "read_only"
	// ModeImportOnly: the directory owns the account lifecycle and the
	// password; mapped attributes are imported when the account is created
	// and are locally owned afterwards (synchronization reports differences
	// as divergence findings and never overwrites them).
	ModeImportOnly = "import_only"
	// ModeWriteBack: like read_only, except that the attributes listed in
	// write_back_attributes are locally editable and every local edit is
	// written to the directory first; a failed write refuses the edit.
	ModeWriteBack = "write_back"
)

// Attribute authorities (USR-022, PROV-017).
const (
	AuthorityDirectory = "directory"  // externally managed: local edits refused
	AuthorityLocal     = "local"      // locally owned (imported once at most)
	AuthorityWriteBack = "write_back" // locally editable, written to the directory
)

// Directory dialects select defaults for attributes, filters and change
// tracking.
const (
	DialectActiveDirectory = "active_directory"
	DialectOpenLDAP        = "openldap"
)

// localAttributes are the account attributes a directory attribute can map
// to. Phone numbers are deliberately absent: an imported number would need
// proof of control before it could be used (USR-004).
var localAttributes = []string{"username", "email", "display_name", "given_name", "family_name", "locale", "zoneinfo"}

var profileKey = regexp.MustCompile(`^profile\.[a-z][a-z0-9_]{0,63}$`)

var ldapAttrName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$|^[0-9]+(\.[0-9]+)+$`)

func validLocalAttribute(a string) bool {
	return slices.Contains(localAttributes, a) || profileKey.MatchString(a)
}

// LDAPConfig configures an LDAP or Active Directory connector (PROV-011). It
// never holds the service account password, which is stored encrypted and is
// write-only through the API (PROV-018).
type LDAPConfig struct {
	// Endpoints are ldaps:// or ldap:// URLs tried in order; the next one is
	// used only after a transport failure (PROV-014).
	Endpoints []string `json:"endpoints"`
	// StartTLS upgrades ldap:// endpoints before any credential is sent. It
	// may be false only in development mode.
	StartTLS *bool `json:"start_tls,omitempty"`
	// CACertificatesPEM are trusted roots for this connector, added to the
	// roots from directory.ca_file and the system.
	CACertificatesPEM       string `json:"ca_certificates_pem,omitempty"`
	ConnectTimeoutSeconds   int    `json:"connect_timeout_seconds,omitempty"`
	OperationTimeoutSeconds int    `json:"operation_timeout_seconds,omitempty"`
	BindDN                  string `json:"bind_dn"`
	Dialect                 string `json:"dialect"`
	UserBaseDN              string `json:"user_base_dn"`
	UserScope               string `json:"user_scope,omitempty"`
	UserFilter              string `json:"user_filter,omitempty"`
	// IDAttribute is the immutable source identifier (objectGUID, entryUUID).
	IDAttribute string `json:"id_attribute,omitempty"`
	// LoginAttributes are matched against a sign-in identifier when an
	// account is provisioned at first sign-in.
	LoginAttributes []string `json:"login_attributes,omitempty"`
	// AttributeMapping maps local attributes to directory attributes.
	AttributeMapping    map[string]string `json:"attribute_mapping,omitempty"`
	Mode                string            `json:"mode,omitempty"`
	AttributeAuthority  map[string]string `json:"attribute_authority,omitempty"`
	WriteBackAttributes []string          `json:"write_back_attributes,omitempty"`
	// DisabledAttribute and DisabledValues mark disabled entries in
	// directories other than Active Directory (whose userAccountControl is
	// always honored).
	DisabledAttribute string   `json:"disabled_attribute,omitempty"`
	DisabledValues    []string `json:"disabled_values,omitempty"`
	// ChangeTracking selects incremental synchronization: usn (Active
	// Directory uSNChanged), modify_timestamp, or none (full only).
	ChangeTracking string `json:"change_tracking,omitempty"`
	PageSize       int    `json:"page_size,omitempty"`
	// MaxEntries lowers directory.max_entries_per_run for this connector
	// (0: the deployment bound); it never raises it.
	MaxEntries int `json:"max_entries,omitempty"`
	// Group mapping (organization connectors only, PROV-007).
	GroupBaseDN          string `json:"group_base_dn,omitempty"`
	GroupFilter          string `json:"group_filter,omitempty"`
	GroupNameAttribute   string `json:"group_name_attribute,omitempty"`
	GroupMemberAttribute string `json:"group_member_attribute,omitempty"`
	// JITProvisioning imports an account at its first successful sign-in.
	JITProvisioning bool `json:"jit_provisioning"`
	// Schedules in seconds (0: not scheduled).
	IncrementalIntervalSeconds int `json:"incremental_interval_seconds,omitempty"`
	FullIntervalSeconds        int `json:"full_interval_seconds,omitempty"`
	// Deletion safety (PROV-012): a full run refuses to deprovision more than
	// this share of linked accounts (or more than the count, when set)
	// without an explicit override.
	DeletionThresholdPercent int    `json:"deletion_threshold_percent,omitempty"`
	DeletionThresholdCount   int    `json:"deletion_threshold_count,omitempty"`
	DeprovisionAction        string `json:"deprovision_action,omitempty"`
}

// OutboundConfig configures an outbound SCIM 2.0 connector (PROV-010). The
// downstream bearer token is stored encrypted and is write-only.
type OutboundConfig struct {
	BaseURL             string `json:"base_url"`
	AllowPrivateNetwork bool   `json:"allow_private_network"`
	TimeoutSeconds      int    `json:"timeout_seconds,omitempty"`
	MaxAttempts         int    `json:"max_attempts,omitempty"`
	// Eligibility: realm connectors push accounts with an active membership
	// in one of EligibleOrganizationIDs (every non-guest account when empty);
	// organization connectors push their organization's members, optionally
	// only members of EligibleGroupIDs.
	EligibleOrganizationIDs []string `json:"eligible_organization_ids,omitempty"`
	EligibleGroupIDs        []string `json:"eligible_group_ids,omitempty"`
	// ExcludeCreatedVia skips accounts by provenance, for example accounts an
	// inbound connector created from the same downstream system, so a change
	// never travels in a loop (PROV-017).
	ExcludeCreatedVia []string `json:"exclude_created_via,omitempty"`
	// AttributeMapping maps SCIM attributes to local sources.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	// DeprovisionAction is deactivate (active=false) or delete.
	DeprovisionAction        string   `json:"deprovision_action,omitempty"`
	PushGroupIDs             []string `json:"push_group_ids,omitempty"`
	ReconcileIntervalSeconds int      `json:"reconcile_interval_seconds,omitempty"`
}

// scimTargets are the SCIM attributes an outbound mapping may set.
var scimTargets = []string{"userName", "displayName", "name.givenName", "name.familyName", "emails", "locale", "timezone", "title", "externalId"}

// outboundSources are the local values an outbound mapping may read.
var outboundSources = []string{"username", "email", "display_name", "given_name", "family_name", "locale", "zoneinfo", "user_id"}

func boolp(b bool) *bool { return &b }

// normalize applies dialect defaults and validates the definition. orgBound
// reports an organization connector; production refuses cleartext transport.
func (c *LDAPConfig) normalize(orgBound, production bool) *problem.Error {
	bad := func(field, msg string) *problem.Error { return problem.ErrValidation.WithField("config."+field, msg) }
	if c.Dialect == "" {
		c.Dialect = DialectOpenLDAP
	}
	if c.Dialect != DialectActiveDirectory && c.Dialect != DialectOpenLDAP {
		return bad("dialect", "active_directory or openldap")
	}
	ad := c.Dialect == DialectActiveDirectory
	if len(c.Endpoints) == 0 || len(c.Endpoints) > 8 {
		return bad("endpoints", "1 to 8 ldaps:// or ldap:// URLs")
	}
	if c.StartTLS == nil {
		c.StartTLS = boolp(true)
	}
	for _, e := range c.Endpoints {
		u, err := url.Parse(e)
		if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.Fragment != "" {
			return bad("endpoints", "each endpoint is ldaps://host[:port] or ldap://host[:port] without credentials, path or query")
		}
		// Credentials never cross a cleartext connection outside
		// development (PROV-011).
		if u.Scheme == "ldap" && !*c.StartTLS && production {
			return bad("start_tls", "ldap:// endpoints require StartTLS outside development mode; use ldaps:// or start_tls")
		}
	}
	if c.CACertificatesPEM != "" {
		if len(c.CACertificatesPEM) > 64<<10 || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACertificatesPEM)) {
			return bad("ca_certificates_pem", "PEM certificates (at most 64 KiB)")
		}
	}
	if c.ConnectTimeoutSeconds < 0 || c.ConnectTimeoutSeconds > 60 || c.OperationTimeoutSeconds < 0 || c.OperationTimeoutSeconds > 120 {
		return bad("connect_timeout_seconds", "connect timeout 0..60 s, operation timeout 0..120 s (0: deployment default)")
	}
	if _, err := ldap.ParseDN(c.BindDN); err != nil || strings.TrimSpace(c.BindDN) == "" || len(c.BindDN) > 1024 {
		return bad("bind_dn", "a distinguished name")
	}
	if _, err := ldap.ParseDN(c.UserBaseDN); err != nil || strings.TrimSpace(c.UserBaseDN) == "" || len(c.UserBaseDN) > 1024 {
		return bad("user_base_dn", "a distinguished name")
	}
	if c.UserScope == "" {
		c.UserScope = "sub"
	}
	if c.UserScope != "sub" && c.UserScope != "one" {
		return bad("user_scope", "sub or one")
	}
	if c.UserFilter == "" {
		c.UserFilter = "(objectClass=inetOrgPerson)"
		if ad {
			c.UserFilter = "(&(objectCategory=person)(objectClass=user))"
		}
	}
	// Operator filters are compiled now, so a malformed filter is refused at
	// configuration time rather than at the first run.
	if _, err := ldap.CompileFilter(c.UserFilter); err != nil || len(c.UserFilter) > 2048 {
		return bad("user_filter", "a valid RFC 4515 filter")
	}
	if c.IDAttribute == "" {
		c.IDAttribute = "entryUUID"
		if ad {
			c.IDAttribute = "objectGUID"
		}
	}
	if !ldapAttrName.MatchString(c.IDAttribute) {
		return bad("id_attribute", "an attribute name")
	}
	if len(c.AttributeMapping) == 0 {
		c.AttributeMapping = map[string]string{"username": "uid", "email": "mail", "display_name": "displayName", "given_name": "givenName", "family_name": "sn"}
		if ad {
			c.AttributeMapping["username"] = "sAMAccountName"
		}
	}
	if len(c.AttributeMapping) > 32 {
		return bad("attribute_mapping", "at most 32 attributes")
	}
	for local, remote := range c.AttributeMapping {
		if !validLocalAttribute(local) {
			return bad("attribute_mapping", "unknown local attribute "+local+" (username, email, display_name, given_name, family_name, locale, zoneinfo or profile.<name>)")
		}
		if !ldapAttrName.MatchString(remote) {
			return bad("attribute_mapping", "invalid directory attribute for "+local)
		}
	}
	if len(c.LoginAttributes) == 0 {
		c.LoginAttributes = []string{"uid", "mail"}
		if ad {
			c.LoginAttributes = []string{"sAMAccountName", "userPrincipalName", "mail"}
		}
	}
	if len(c.LoginAttributes) > 4 {
		return bad("login_attributes", "at most 4 attributes")
	}
	for _, a := range c.LoginAttributes {
		if !ldapAttrName.MatchString(a) {
			return bad("login_attributes", "invalid attribute "+a)
		}
	}
	if c.Mode == "" {
		c.Mode = ModeReadOnly
	}
	if c.Mode != ModeReadOnly && c.Mode != ModeImportOnly && c.Mode != ModeWriteBack {
		return bad("mode", "read_only, import_only or write_back")
	}
	for attr, auth := range c.AttributeAuthority {
		if _, mapped := c.AttributeMapping[attr]; !mapped {
			return bad("attribute_authority", attr+" is not mapped")
		}
		if auth != AuthorityDirectory && auth != AuthorityLocal {
			return bad("attribute_authority", "directory or local (write-back is declared with write_back_attributes)")
		}
	}
	for _, attr := range c.WriteBackAttributes {
		if c.Mode != ModeWriteBack {
			return bad("write_back_attributes", "only in write_back mode (PROV-013)")
		}
		if _, mapped := c.AttributeMapping[attr]; !mapped {
			return bad("write_back_attributes", attr+" is not mapped")
		}
		// Identifiers and passwords are never written back: a changed
		// identifier needs proof of control, and password write-back needs a
		// reviewed connector and transport policy (PROV-013).
		if attr == "username" || attr == "email" {
			return bad("write_back_attributes", attr+" cannot be written back")
		}
		if c.AttributeAuthority[attr] == AuthorityLocal {
			return bad("write_back_attributes", attr+" is declared local")
		}
	}
	if c.DisabledAttribute != "" && !ldapAttrName.MatchString(c.DisabledAttribute) {
		return bad("disabled_attribute", "an attribute name")
	}
	if c.ChangeTracking == "" {
		c.ChangeTracking = "modify_timestamp"
		if ad {
			c.ChangeTracking = "usn"
		}
	}
	if c.ChangeTracking != "usn" && c.ChangeTracking != "modify_timestamp" && c.ChangeTracking != "none" {
		return bad("change_tracking", "usn, modify_timestamp or none")
	}
	if c.PageSize == 0 {
		c.PageSize = 500
	}
	if c.PageSize < 1 || c.PageSize > 5000 {
		return bad("page_size", "1 to 5000")
	}
	if c.MaxEntries < 0 || c.MaxEntries > 1_000_000 {
		return bad("max_entries", "0 (deployment default) to 1000000")
	}
	if c.GroupBaseDN == "" {
		c.GroupBaseDN = c.UserBaseDN
	}
	if _, err := ldap.ParseDN(c.GroupBaseDN); err != nil {
		return bad("group_base_dn", "a distinguished name")
	}
	if c.GroupFilter == "" {
		c.GroupFilter = "(objectClass=groupOfNames)"
		if ad {
			c.GroupFilter = "(objectClass=group)"
		}
	}
	if _, err := ldap.CompileFilter(c.GroupFilter); err != nil {
		return bad("group_filter", "a valid RFC 4515 filter")
	}
	if c.GroupNameAttribute == "" {
		c.GroupNameAttribute = "cn"
	}
	if c.GroupMemberAttribute == "" {
		c.GroupMemberAttribute = "member"
	}
	if !ldapAttrName.MatchString(c.GroupNameAttribute) || (c.GroupMemberAttribute != "member" && c.GroupMemberAttribute != "uniqueMember" && c.GroupMemberAttribute != "memberUid") {
		return bad("group_member_attribute", "member, uniqueMember or memberUid")
	}
	if c.JITProvisioning && orgBound {
		// First sign-in provisioning sends the password of every not yet
		// imported identifier to the directory: only a realm directory, which
		// realm administrators configure, may receive it — never one a
		// tenant administrator points at a server of their choosing.
		return bad("jit_provisioning", "available for realm connectors only")
	}
	if c.IncrementalIntervalSeconds != 0 && (c.IncrementalIntervalSeconds < 60 || c.IncrementalIntervalSeconds > 7*86400) {
		return bad("incremental_interval_seconds", "0 or 60 to 604800")
	}
	if c.FullIntervalSeconds != 0 && (c.FullIntervalSeconds < 300 || c.FullIntervalSeconds > 30*86400) {
		return bad("full_interval_seconds", "0 or 300 to 2592000")
	}
	if c.DeletionThresholdPercent == 0 {
		c.DeletionThresholdPercent = 20
	}
	if c.DeletionThresholdPercent < 1 || c.DeletionThresholdPercent > 100 || c.DeletionThresholdCount < 0 {
		return bad("deletion_threshold_percent", "1 to 100")
	}
	if orgBound {
		if c.DeprovisionAction == "" {
			c.DeprovisionAction = "remove_membership"
		}
		if c.DeprovisionAction != "remove_membership" && c.DeprovisionAction != "suspend_membership" && c.DeprovisionAction != "report_only" {
			return bad("deprovision_action", "remove_membership, suspend_membership or report_only")
		}
	} else {
		if c.DeprovisionAction == "" {
			c.DeprovisionAction = "suspend_account"
		}
		if c.DeprovisionAction != "suspend_account" && c.DeprovisionAction != "report_only" {
			return bad("deprovision_action", "suspend_account or report_only (realm directories never delete accounts)")
		}
	}
	return nil
}

// authority returns the authority of a mapped local attribute; unmapped
// attributes are local.
func (c *LDAPConfig) authority(attr string) string {
	if _, mapped := c.AttributeMapping[attr]; !mapped {
		return AuthorityLocal
	}
	if a := c.AttributeAuthority[attr]; a == AuthorityLocal {
		return AuthorityLocal
	}
	switch c.Mode {
	case ModeImportOnly:
		return AuthorityLocal
	case ModeWriteBack:
		if slices.Contains(c.WriteBackAttributes, attr) {
			return AuthorityWriteBack
		}
	}
	return AuthorityDirectory
}

func (c *OutboundConfig) normalize(orgBound bool, policy egress.Policy) *problem.Error {
	bad := func(field, msg string) *problem.Error { return problem.ErrValidation.WithField("config."+field, msg) }
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return bad("base_url", "an absolute https URL without credentials, query or fragment")
	}
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	pol := policy
	if c.AllowPrivateNetwork && !policy.AllowPrivate && len(policy.AllowCIDRs) == 0 {
		return bad("allow_private_network", "the operator egress policy does not permit private destinations (EXT-007)")
	}
	if !c.AllowPrivateNetwork {
		pol.AllowPrivate, pol.AllowCIDRs = false, nil
	}
	if err := pol.ValidateURL(c.BaseURL); err != nil {
		return bad("base_url", "destination is not allowed by the egress policy")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 10
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 {
		return bad("timeout_seconds", "1 to 60")
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 8
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > 20 {
		return bad("max_attempts", "1 to 20")
	}
	if orgBound && len(c.EligibleOrganizationIDs) > 0 {
		return bad("eligible_organization_ids", "an organization connector pushes only its own organization's members")
	}
	if !orgBound && (len(c.EligibleGroupIDs) > 0 || len(c.PushGroupIDs) > 0) {
		return bad("eligible_group_ids", "groups belong to organizations; use an organization connector")
	}
	if len(c.EligibleOrganizationIDs) > 50 || len(c.EligibleGroupIDs) > 50 || len(c.PushGroupIDs) > 50 || len(c.ExcludeCreatedVia) > 20 {
		return bad("eligible_group_ids", "at most 50 organizations or groups and 20 exclusions")
	}
	if len(c.AttributeMapping) == 0 {
		c.AttributeMapping = map[string]string{"userName": "username", "displayName": "display_name", "name.givenName": "given_name",
			"name.familyName": "family_name", "emails": "email", "externalId": "user_id"}
	}
	for target, source := range c.AttributeMapping {
		if !slices.Contains(scimTargets, target) {
			return bad("attribute_mapping", "unknown SCIM attribute "+target)
		}
		if !slices.Contains(outboundSources, source) && !profileKey.MatchString(source) {
			return bad("attribute_mapping", "unknown local source "+source)
		}
	}
	if _, ok := c.AttributeMapping["userName"]; !ok {
		return bad("attribute_mapping", "userName must be mapped")
	}
	// The downstream externalId is always the local account ID: retries
	// find their own earlier resource by it, and never adopt someone
	// else's (idempotency, PROV-010).
	c.AttributeMapping["externalId"] = "user_id"
	if c.DeprovisionAction == "" {
		c.DeprovisionAction = "deactivate"
	}
	if c.DeprovisionAction != "deactivate" && c.DeprovisionAction != "delete" {
		return bad("deprovision_action", "deactivate or delete")
	}
	if c.ReconcileIntervalSeconds != 0 && (c.ReconcileIntervalSeconds < 300 || c.ReconcileIntervalSeconds > 30*86400) {
		return bad("reconcile_interval_seconds", "0 or 300 to 2592000")
	}
	return nil
}
