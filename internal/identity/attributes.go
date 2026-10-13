package identity

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/proudbase/proudauth/internal/platform/problem"
)

// AttributeDef is a typed custom-attribute definition (USR-007).
type AttributeDef struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"` // string | number | boolean | enum
	MaxLength    int      `json:"max_length,omitempty"`
	Enum         []string `json:"enum,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
	Required     bool     `json:"required,omitempty"`
	UserEditable bool     `json:"user_editable"`
	Visibility   string   `json:"visibility"` // self | admin | internal
	Source       string   `json:"source"`     // local | federation | directory
	Claimable    bool     `json:"claimable"`  // eligible for claim mapping
}

// AttributeSchema is the realm's custom attribute schema.
type AttributeSchema struct {
	Attributes []AttributeDef `json:"attributes"`
}

var attrName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// MaxAttributes bounds a realm schema.
const MaxAttributes = 50

// Validate checks a schema definition (USR-007): bounded size, unique snake_case
// names, known types, compilable bounded patterns and explicit visibility and
// source values.
func (s *AttributeSchema) Validate() *problem.Error {
	if len(s.Attributes) > MaxAttributes {
		return problem.ErrValidation.WithField("profile.attributes", "at most 50 attributes")
	}
	seen := map[string]bool{}
	for i := range s.Attributes {
		d := &s.Attributes[i]
		field := fmt.Sprintf("profile.attributes[%d]", i)
		if !attrName.MatchString(d.Name) || seen[d.Name] {
			return problem.ErrValidation.WithField(field+".name", "unique snake_case name required")
		}
		seen[d.Name] = true
		switch d.Type {
		case "", "string", "number", "boolean":
		case "enum":
			if len(d.Enum) == 0 || len(d.Enum) > 100 {
				return problem.ErrValidation.WithField(field+".enum", "1..100 values")
			}
		default:
			return problem.ErrValidation.WithField(field+".type", "string, number, boolean or enum")
		}
		if d.MaxLength < 0 || d.MaxLength > 4096 {
			return problem.ErrValidation.WithField(field+".max_length", "0..4096")
		}
		if d.Pattern != "" {
			if len(d.Pattern) > 200 {
				return problem.ErrValidation.WithField(field+".pattern", "at most 200 characters")
			}
			if _, err := regexp.Compile(d.Pattern); err != nil {
				return problem.ErrValidation.WithField(field+".pattern", "invalid regular expression")
			}
		}
		switch d.Visibility {
		case "":
			d.Visibility = "self"
		case "self", "admin", "internal":
		default:
			return problem.ErrValidation.WithField(field+".visibility", "self, admin or internal")
		}
		switch d.Source {
		case "":
			d.Source = "local"
		case "local", "federation", "directory":
		default:
			return problem.ErrValidation.WithField(field+".source", "local, federation or directory")
		}
		if d.Visibility != "self" && d.UserEditable {
			return problem.ErrValidation.WithField(field+".user_editable", "only self-visible attributes can be user-editable")
		}
		// Token claims carry only values the user cannot set themselves
		// (APP-011): relying parties may base decisions on them.
		if d.Claimable && d.UserEditable {
			return problem.ErrValidation.WithField(field+".claimable", "a user-editable attribute cannot be released in token claims")
		}
	}
	return nil
}

func (s *AttributeSchema) def(name string) *AttributeDef {
	for i := range s.Attributes {
		if s.Attributes[i].Name == name {
			return &s.Attributes[i]
		}
	}
	return nil
}

// ValidateSelfEdit rejects edits to attributes that are not user-editable or that
// are owned by an external source, and type-checks values. Unknown attributes are
// rejected so self-service can never introduce attributes a policy might consume
// (TEST-013).
func (s *AttributeSchema) ValidateSelfEdit(current, patch map[string]any) *problem.Error {
	for k, v := range patch {
		d := s.def(k)
		if d == nil {
			return problem.ErrValidation.WithField("profile."+k, "unknown attribute")
		}
		if !d.UserEditable || d.Source != "" && d.Source != "local" {
			return problem.ErrForbidden.WithDetail(fmt.Sprintf("attribute %s is not user-editable", k))
		}
		if v == nil {
			if d.Required {
				return problem.ErrValidation.WithField("profile."+k, "required")
			}
			continue
		}
		if err := d.check(v); err != "" {
			return problem.ErrValidation.WithField("profile."+k, err)
		}
	}
	return nil
}

func (d *AttributeDef) check(v any) string {
	switch d.Type {
	case "string", "":
		s, ok := v.(string)
		if !ok {
			return "must be a string"
		}
		max := d.MaxLength
		if max == 0 {
			max = 256
		}
		if utf8.RuneCountInString(s) > max {
			return "too long"
		}
		if d.Pattern != "" {
			re, err := regexp.Compile(d.Pattern)
			if err != nil || !re.MatchString(s) {
				return "invalid format"
			}
		}
	case "number":
		if _, ok := v.(float64); !ok {
			return "must be a number"
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return "must be a boolean"
		}
	case "enum":
		s, ok := v.(string)
		if !ok {
			return "must be a string"
		}
		for _, e := range d.Enum {
			if e == s {
				return ""
			}
		}
		return "not an allowed value"
	default:
		return "unsupported type"
	}
	return ""
}

// Visible returns the profile attributes a viewer may read (USR-002,
// USR-007): the user sees self-visible attributes; administrators also see
// admin-visible ones; internal attributes are never returned by the APIs.
// Attributes the schema does not define are shown to administrators only.
// Without a schema every attribute is visible.
func (s *AttributeSchema) Visible(profile map[string]any, viewer string) map[string]any {
	if s == nil || len(s.Attributes) == 0 {
		return profile
	}
	out := map[string]any{}
	for k, v := range profile {
		d := s.def(k)
		switch {
		case d == nil:
			if viewer == "admin" {
				out[k] = v
			}
		case d.Visibility == "self", d.Visibility == "admin" && viewer == "admin":
			out[k] = v
		}
	}
	return out
}

// ValidateAdminEdit type-checks administrator profile edits: unknown
// attributes and values outside their definition are refused (USR-007).
// Administrators may set attributes of any source: they are the authority
// that feeds directory attributes where no connector does.
func (s *AttributeSchema) ValidateAdminEdit(patch map[string]any) *problem.Error {
	if s == nil || len(s.Attributes) == 0 {
		return nil
	}
	for k, v := range patch {
		d := s.def(k)
		if d == nil {
			return problem.ErrValidation.WithField("profile."+k, "unknown attribute")
		}
		if v == nil {
			continue
		}
		if err := d.check(v); err != "" {
			return problem.ErrValidation.WithField("profile."+k, err)
		}
	}
	return nil
}

// Complete reports whether all required attributes are present.
func (s *AttributeSchema) Complete(profile map[string]any) bool {
	for _, d := range s.Attributes {
		if d.Required {
			if v, ok := profile[d.Name]; !ok || v == nil || v == "" {
				return false
			}
		}
	}
	return true
}

// Missing lists required attributes that are absent (REG-007 progressive profiling).
func (s *AttributeSchema) Missing(profile map[string]any) []string {
	var out []string
	for _, d := range s.Attributes {
		if d.Required {
			if v, ok := profile[d.Name]; !ok || v == nil || v == "" {
				out = append(out, d.Name)
			}
		}
	}
	return out
}
