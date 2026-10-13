package realm

import "github.com/proudbase/proudauth/internal/platform/problem"

// Plugin review modes (EXT-014).
const (
	// PluginReviewSecondAdmin (the default) requires an administrator other
	// than the uploader to approve a plugin version before it is installed.
	PluginReviewSecondAdmin = "second_admin"
	// PluginReviewSingleAdmin lets the uploader install without a second
	// review. It is an explicit realm decision, recorded in the audit trail
	// with every installation.
	PluginReviewSingleAdmin = "single_admin"
)

// ExtensionsPolicy governs the realm's extensions.
type ExtensionsPolicy struct {
	// PluginReview is second_admin (default when empty) or single_admin.
	PluginReview string `json:"plugin_review,omitempty"`
	// WorkflowPublishApproval requires an administrator other than a
	// revision's author to approve it before it is published (EXT-015,
	// AZ-018). Workflows created while it is on always require approval.
	WorkflowPublishApproval bool `json:"workflow_publish_approval,omitempty"`
}

// PluginReviewMode returns the effective review mode.
func (p ExtensionsPolicy) PluginReviewMode() string {
	if p.PluginReview == "" {
		return PluginReviewSecondAdmin
	}
	return p.PluginReview
}

func validateExtensions(p ExtensionsPolicy) error {
	switch p.PluginReview {
	case "", PluginReviewSecondAdmin, PluginReviewSingleAdmin:
		return nil
	}
	return problem.ErrValidation.WithField("extensions.plugin_review", "second_admin or single_admin")
}
