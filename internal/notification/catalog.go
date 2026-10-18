package notification

// Template is a localized message template. Variables use {{.name}}; values are
// escaped and never interpreted. Links are built by the server from trusted
// configuration and passed in as data, never from request input (MSG-004).
type Template struct {
	Subject string
	Text    string
	HTML    string
}

// Catalog holds built-in templates by name and locale.
type Catalog struct {
	byKey map[string]Template
}

func (c *Catalog) lookup(name, locale string) (Template, bool) {
	t, ok := c.byKey[name+"/"+locale]
	return t, ok
}

// Variables documents the variables each template may reference.
var Variables = map[string][]string{
	TplEmailVerification:    {"code", "realm", "expires_minutes"},
	TplLoginCode:            {"code", "realm", "expires_minutes"},
	TplMagicLink:            {"link", "realm", "expires_minutes"},
	TplAccountLinkCode:      {"code", "realm", "provider", "expires_minutes"},
	TplAccountLinkMagicLink: {"link", "realm", "provider", "expires_minutes"},
	TplPasswordReset:        {"code", "link", "realm", "expires_minutes"},
	TplPasswordChanged:      {"realm", "time"},
	TplInvitation:           {"organization", "inviter", "link", "code", "realm", "expires_hours"},
	TplMFAChanged:           {"realm", "change", "time"},
	TplNewLogin:             {"realm", "time", "network", "device"},
	TplAccountSuspended:     {"realm", "time"},
	TplSupportAccess:        {"realm", "organization", "time", "expires", "state"},
	TplAccountSetup:         {"realm", "code", "link", "expires_hours"},
	TplRegistrationExists:   {"realm"},
	TplIdentifierChanged:    {"realm", "change", "time"},
	TplRecovery:             {"realm", "change", "time"},
	TplCredentialExpiry:     {"realm", "credential", "expires"},
	TplCredentialsRevoked:   {"realm", "change", "credentials", "time"},
	TplTest:                 {"realm", "time"},
	TplJoinRequest:          {"realm", "organization"},
	TplDeletion:             {"realm", "scheduled"},
	TplSupportApproval:      {"realm", "organization", "time", "expires", "state", "reason"},
	TplRegistrationReview:   {"realm", "decision"},
	TplJoinDecision:         {"realm", "organization", "decision"},
	TplWorkflowNotice:       {"realm", "workflow", "notice", "time"},
}

// DefaultCatalog returns the built-in English and Spanish templates (MSG-006).
func DefaultCatalog() *Catalog {
	c := &Catalog{byKey: map[string]Template{}}
	add := func(name, locale, subject, text string) {
		c.byKey[name+"/"+locale] = Template{Subject: subject, Text: text}
	}
	add(TplEmailVerification, "en", "Your {{.realm}} verification code",
		"Your verification code is {{.code}}. It expires in {{.expires_minutes}} minutes.\n\nIf you did not request this, you can ignore this message.")
	add(TplEmailVerification, "es", "Tu código de verificación de {{.realm}}",
		"Tu código de verificación es {{.code}}. Caduca en {{.expires_minutes}} minutos.\n\nSi no lo solicitaste, ignora este mensaje.")
	add(TplLoginCode, "en", "Your {{.realm}} sign-in code",
		"Your sign-in code is {{.code}}. It expires in {{.expires_minutes}} minutes. Never share this code.")
	add(TplLoginCode, "es", "Tu código de inicio de sesión de {{.realm}}",
		"Tu código de inicio de sesión es {{.code}}. Caduca en {{.expires_minutes}} minutos. Nunca lo compartas.")
	add(TplMagicLink, "en", "Sign in to {{.realm}}",
		"Use this link to continue signing in. You will be asked to confirm before anything happens:\n{{.link}}\n\nIt expires in {{.expires_minutes}} minutes.")
	add(TplAccountLinkCode, "en", "Link a {{.provider}} account to your {{.realm}} account",
		"Someone is signing in with a {{.provider}} account and asked to link it to your {{.realm}} account. Once linked, that {{.provider}} account can sign in to your account.\n\nYour code to link it is {{.code}}. It expires in {{.expires_minutes}} minutes. Enter it only if you are linking your own {{.provider}} account right now; never share it. If this was not you, ignore this message: nothing is linked without the code.")
	add(TplAccountLinkCode, "es", "Vincular una cuenta de {{.provider}} a tu cuenta de {{.realm}}",
		"Alguien está iniciando sesión con una cuenta de {{.provider}} y pidió vincularla a tu cuenta de {{.realm}}. Una vez vinculada, esa cuenta de {{.provider}} podrá iniciar sesión en tu cuenta.\n\nTu código para vincularla es {{.code}}. Caduca en {{.expires_minutes}} minutos. Introdúcelo solo si estás vinculando tu propia cuenta de {{.provider}} ahora; nunca lo compartas. Si no fuiste tú, ignora este mensaje: no se vincula nada sin el código.")
	add(TplAccountLinkMagicLink, "en", "Link a {{.provider}} account to your {{.realm}} account",
		"Someone is signing in with a {{.provider}} account and asked to link it to your {{.realm}} account. Once linked, that {{.provider}} account can sign in to your account.\n\nUse this link only if you are linking your own {{.provider}} account right now. You will be asked to confirm before anything happens:\n{{.link}}\n\nIt expires in {{.expires_minutes}} minutes. If this was not you, ignore this message: nothing is linked without the link.")
	add(TplPasswordReset, "en", "Reset your {{.realm}} password",
		"Use this code to reset your password: {{.code}}\nOr continue here: {{.link}}\nIt expires in {{.expires_minutes}} minutes. Resetting your password does not remove your multi-factor authentication.")
	add(TplPasswordReset, "es", "Restablece tu contraseña de {{.realm}}",
		"Usa este código para restablecer tu contraseña: {{.code}}\nO continúa aquí: {{.link}}\nCaduca en {{.expires_minutes}} minutos.")
	add(TplPasswordChanged, "en", "Your {{.realm}} password was changed",
		"Your password was changed at {{.time}}. If this was not you, recover your account immediately.")
	add(TplInvitation, "en", "You're invited to join {{.organization}}",
		"{{.inviter}} invited you to join {{.organization}} on {{.realm}}.\nReview and accept the invitation here: {{.link}}\nInvitation code: {{.code}}\nThe invitation expires in {{.expires_hours}} hours. Opening the link does not accept it.")
	add(TplInvitation, "es", "Te invitaron a unirte a {{.organization}}",
		"{{.inviter}} te invitó a unirte a {{.organization}} en {{.realm}}.\nRevisa y acepta la invitación aquí: {{.link}}\nCódigo: {{.code}}\nCaduca en {{.expires_hours}} horas.")
	add(TplMFAChanged, "en", "Your {{.realm}} security settings changed",
		"A multi-factor authentication change was made to your account: {{.change}} at {{.time}}. If this was not you, recover your account immediately.")
	add(TplNewLogin, "en", "New sign-in to your {{.realm}} account",
		"A new sign-in occurred at {{.time}} from {{.network}} ({{.device}}). If this was not you, revoke the session and change your password.")
	add(TplAccountSuspended, "en", "Your {{.realm}} account was suspended",
		"Your account was suspended at {{.time}}. Contact your administrator for assistance.")
	add(TplSupportAccess, "en", "Support access to your {{.realm}} account",
		"A support operator was granted {{.state}} access to your account in {{.organization}} at {{.time}}. Access ends no later than {{.expires}}. You can review or end support access from your account security settings.")
	add(TplAccountSetup, "en", "Set up your {{.realm}} account",
		"An account was created for you. Complete setup with this code: {{.code}}\nOr continue here: {{.link}}\nThis link expires in {{.expires_hours}} hours.")
	add(TplRegistrationExists, "en", "Sign-up attempt on {{.realm}}",
		"Someone tried to create an account with this address, but an account already exists. If this was you, sign in or reset your password instead. If not, no action is needed.")
	add(TplIdentifierChanged, "en", "Your {{.realm}} contact details changed",
		"A change was made to your sign-in identifiers: {{.change}} at {{.time}}. If this was not you, recover your account immediately.")
	add(TplRecovery, "en", "Account recovery on {{.realm}}",
		"An account recovery action occurred: {{.change}} at {{.time}}. If this was not you, contact support immediately.")
	add(TplCredentialExpiry, "en", "A {{.realm}} credential expires soon",
		"The credential {{.credential}} expires at {{.expires}}. Rotate it before it expires.")
	add(TplCredentialsRevoked, "en", "Your {{.realm}} personal access tokens were revoked",
		"These personal access tokens and API keys of your account were revoked at {{.time}} after {{.change}}: {{.credentials}}.\n\nScripts and integrations that use them stop working. If you still need them, sign in and create new ones. If you did not expect this, contact your administrator.")
	add(TplTest, "en", "{{.realm}} delivery test", "This is a configuration test sent at {{.time}}. Provider acceptance does not prove inbox delivery.")
	add(TplRegistrationReview, "en", "Your {{.realm}} registration was reviewed",
		"Your registration was {{.decision}}. If it was approved you can now sign in.")
	add(TplSupportApproval, "en", "Approve support access to your {{.realm}} account?",
		"A support operator asked for {{.state}} access to your account in {{.organization}} at {{.time}}. Reason given: {{.reason}}. Approve or deny the request in your account security settings before {{.expires}}; nothing happens unless you approve.")
	add(TplJoinRequest, "en", "New request to join {{.organization}}", "A user requested to join {{.organization}} on {{.realm}}. Review it in your administration tools.")
	add(TplWorkflowNotice, "en", "{{.realm}}: {{.workflow}}",
		"{{.notice}}\n\nThis notice was sent at {{.time}} by the {{.workflow}} process of {{.realm}}. If you did not expect it, contact your administrator.")
	add(TplJoinDecision, "en", "Your request to join {{.organization}} was {{.decision}}",
		"Your request to join {{.organization}} on {{.realm}} was {{.decision}}.")
	add(TplDeletion, "en", "Your {{.realm}} account deletion is scheduled",
		"Your account is scheduled for deletion at {{.scheduled}}. Sign in and cancel the request before then if this was not intended.")
	return c
}
