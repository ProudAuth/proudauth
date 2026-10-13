package provisioning

// SCIM discovery documents (RFC 7643 §5-§7, RFC 7644 §4). They advertise
// exactly what is implemented (PROV-009): PATCH, filtering and ETags, and no
// bulk, sort or password change.

// MaxResults bounds one list response.
const MaxResults = 200

// ServiceProviderConfig describes this server's SCIM capabilities.
func ServiceProviderConfig(docsURL string) map[string]any {
	return map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": docsURL,
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": MaxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Connector token", "primary": true,
			"description": "The bearer token issued for this provisioning connector (pa_scim_...)."}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig"},
	}
}

// ResourceTypes lists the resource types a connector may use.
func ResourceTypes(c *Connector, base string) []map[string]any {
	var out []map[string]any
	if c.Allows("User") {
		out = append(out, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "schema": SchemaUser, "meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"}})
	}
	if c.Allows("Group") {
		out = append(out, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "schema": SchemaGroup, "meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"}})
	}
	return out
}

func attr(name, typ string, extra map[string]any) map[string]any {
	a := map[string]any{"name": name, "type": typ, "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite",
		"returned": "default", "uniqueness": "none"}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

// Schemas describes the attributes stored; others are accepted and ignored.
func Schemas() []map[string]any {
	user := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": SchemaUser, "name": "User",
		"description": "User account. Only the attributes listed are stored; others are accepted and ignored.",
		"attributes": []map[string]any{
			attr("userName", "string", map[string]any{"required": true, "uniqueness": "server"}),
			attr("name", "complex", map[string]any{"subAttributes": []map[string]any{attr("givenName", "string", nil), attr("familyName", "string", nil)}}),
			attr("displayName", "string", nil),
			attr("emails", "complex", map[string]any{"multiValued": true, "subAttributes": []map[string]any{attr("value", "string", nil),
				attr("type", "string", nil), attr("primary", "boolean", nil)}}),
			attr("active", "boolean", map[string]any{"description": "Membership state in the connector's organization, never the realm-wide account state."}),
			attr("externalId", "string", map[string]any{"caseExact": true}),
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	group := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": SchemaGroup, "name": "Group",
		"description": "Group in the connector's organization.",
		"attributes": []map[string]any{
			attr("displayName", "string", map[string]any{"required": true, "uniqueness": "server"}),
			attr("members", "complex", map[string]any{"multiValued": true, "subAttributes": []map[string]any{
				attr("value", "string", map[string]any{"mutability": "immutable"}), attr("display", "string", map[string]any{"mutability": "readOnly"})}}),
			attr("externalId", "string", map[string]any{"caseExact": true}),
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	return []map[string]any{user, group}
}
