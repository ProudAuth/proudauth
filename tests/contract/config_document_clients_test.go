package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/application"
)

// TestConfigDocumentClientAuthMethods keeps the configuration-document
// schema's client rules for token_endpoint_auth_method in step with what the
// server accepts (application.ClientInput.Normalize): in particular a
// machine client whose only grant is jwt-bearer (workload federation,
// MCH-011) uses "none", the export writes it so, and the exported document
// must validate (SDK-012, MIG-014).
func TestConfigDocumentClientAuthMethods(t *testing.T) {
	raw, err := os.ReadFile("../../api/schemas/config-document.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	clientSchema := root["$defs"].(map[string]any)["ClientInput"].(map[string]any)
	const jwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	cases := []struct {
		name   string
		typ    string
		method string
		grants []string
	}{
		{"workload federation client", "machine", "none", []string{jwtBearer}},
		{"secretless machine client with client credentials", "machine", "none", []string{"client_credentials"}},
		{"secretless machine client with a second grant", "machine", "none", []string{jwtBearer, "client_credentials"}},
		{"secretless machine client with default grants", "machine", "none", nil},
		{"machine client with a secret", "machine", "client_secret_basic", []string{"client_credentials"}},
		{"machine client with a secret and jwt-bearer", "machine", "client_secret_basic", []string{jwtBearer}},
		{"secretless confidential client", "confidential", "none", []string{"authorization_code"}},
		{"public browser client", "public_browser", "none", []string{"authorization_code"}},
	}
	for _, tc := range cases {
		doc := map[string]any{"client_id": "c", "name": "c", "client_type": tc.typ, "token_endpoint_auth_method": tc.method,
			"redirect_uris": []any{"https://app.example/cb"}, "service_principal": "svc"}
		in := application.ClientInput{ClientID: "c", Name: "c", Type: tc.typ, AuthMethod: tc.method, RedirectURIs: []string{"https://app.example/cb"},
			ServicePrincipalID: "svc_1"}
		if tc.grants != nil {
			gs := make([]any, len(tc.grants))
			for i, g := range tc.grants {
				gs[i] = g
			}
			doc["grant_types"] = gs
			in.GrantTypes = append([]string(nil), tc.grants...)
		}
		var docJSON any
		b, _ := json.Marshal(doc)
		_ = json.Unmarshal(b, &docJSON)
		schemaOK := true
		for _, cond := range clientSchema["allOf"].([]any) {
			if !validates(root, cond, docJSON) {
				schemaOK = false
			}
		}
		perr := in.Normalize()
		serverOK := perr == nil
		if perr != nil && !strings.Contains(jsonString(perr), "token_endpoint_auth_method") {
			t.Fatalf("%s: the server refused for another reason: %s", tc.name, jsonString(perr))
		}
		if schemaOK != serverOK {
			t.Errorf("%s: the schema says valid=%v, the server accepts=%v", tc.name, schemaOK, serverOK)
		}
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// validates evaluates the subset of JSON Schema 2020-12 the client rules of
// config-document.schema.json use. Annotations ($comment, description) are
// ignored; an unknown assertion keyword fails the test run loudly through a
// panic so the evaluator is never silently too lenient.
func validates(root map[string]any, schema any, v any) bool {
	s, ok := schema.(map[string]any)
	if !ok {
		return schema != false
	}
	for k, arg := range s {
		switch k {
		case "$comment", "description", "title", "examples", "default", "then":
		case "$ref":
			ref := strings.TrimPrefix(arg.(string), "#/$defs/")
			if !validates(root, root["$defs"].(map[string]any)[ref], v) {
				return false
			}
		case "if":
			if validates(root, arg, v) {
				if th, ok := s["then"]; ok && !validates(root, th, v) {
					return false
				}
			}
		case "allOf":
			for _, sub := range arg.([]any) {
				if !validates(root, sub, v) {
					return false
				}
			}
		case "anyOf":
			matched := false
			for _, sub := range arg.([]any) {
				if validates(root, sub, v) {
					matched = true
				}
			}
			if !matched {
				return false
			}
		case "not":
			if validates(root, arg, v) {
				return false
			}
		case "const":
			if !reflect.DeepEqual(arg, v) {
				return false
			}
		case "enum":
			found := false
			for _, e := range arg.([]any) {
				if reflect.DeepEqual(e, v) {
					found = true
				}
			}
			if !found {
				return false
			}
		case "type":
			if !hasType(arg.(string), v) {
				return false
			}
		case "required":
			obj, isObj := v.(map[string]any)
			if isObj {
				for _, r := range arg.([]any) {
					if _, ok := obj[r.(string)]; !ok {
						return false
					}
				}
			}
		case "properties":
			if obj, isObj := v.(map[string]any); isObj {
				for name, sub := range arg.(map[string]any) {
					if pv, ok := obj[name]; ok && !validates(root, sub, pv) {
						return false
					}
				}
			}
		case "items":
			if arr, isArr := v.([]any); isArr {
				for _, it := range arr {
					if !validates(root, arg, it) {
						return false
					}
				}
			}
		case "contains":
			if arr, isArr := v.([]any); isArr {
				found := false
				for _, it := range arr {
					if validates(root, arg, it) {
						found = true
					}
				}
				if !found {
					return false
				}
			}
		case "minItems":
			if arr, isArr := v.([]any); isArr && float64(len(arr)) < arg.(float64) {
				return false
			}
		case "minLength":
			if str, isStr := v.(string); isStr && float64(len([]rune(str))) < arg.(float64) {
				return false
			}
		case "pattern":
			if str, isStr := v.(string); isStr && !regexp.MustCompile(arg.(string)).MatchString(str) {
				return false
			}
		default:
			panic("schema keyword not supported by the test evaluator: " + k)
		}
	}
	return true
}

func hasType(typ string, v any) bool {
	switch typ {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer", "number":
		_, ok := v.(float64)
		return ok
	case "null":
		return v == nil
	}
	return false
}
