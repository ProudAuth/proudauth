package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/proudbase/proudauth-sdk-go/admin"
)

// Typed administration commands (SDK-003): every command calls the public
// administration API with the stored token, so the same permission checks,
// MFA requirements and audit apply as for any other API client.
func init() {
	register("clients", "list OAuth clients", func(args []string) error {
		fs := flag.NewFlagSet("clients", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		return c.Clients(context.Background(), func(cl admin.OAuthClient) error {
			fmt.Printf("%s  %-24s  %-16s %-10s %s\n", cl.ID, cl.ClientID, cl.Type, cl.State, cl.Name)
			return nil
		})
	})
	register("roles", "list roles of a boundary (realm, organization or project)", func(args []string) error {
		fs := flag.NewFlagSet("roles", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		boundary := fs.String("boundary", "organization", "realm, organization or project")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		roles, err := c.Roles(context.Background(), *boundary)
		if err != nil {
			return err
		}
		for _, r := range roles {
			fmt.Printf("%s  %-24s  %s\n", r.ID, r.Name, strings.Join(r.Permissions, ","))
		}
		return nil
	})
	register("assign-role", "assign a role to a user or service principal (ceilings and approvals apply)", func(args []string) error {
		fs := flag.NewFlagSet("assign-role", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		role := fs.String("role", "", "role ID")
		subject := fs.String("subject", "", "user (usr_) or service principal (svc_) ID")
		org := fs.String("org", "", "organization ID for organization roles (omit for realm roles)")
		_ = fs.Parse(args)
		if *role == "" || *subject == "" {
			return errors.New("--role and --subject are required")
		}
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		subjType := "user"
		if strings.HasPrefix(*subject, "svc_") {
			subjType = "service_principal"
		}
		// A realm role carries no scope: the server applies the realm of the
		// request. The --realm flag is the realm's name, while a realm scope
		// names the realm's ID, so sending the name was always refused.
		scopeType, scopeID := "", ""
		if *org != "" {
			scopeType, scopeID = "organization", *org
		}
		out, err := c.Assign(context.Background(), *role, subjType, *subject, scopeType, scopeID)
		if err != nil {
			return err
		}
		return printJSON(out)
	})
	register("grant-scopes", "set the scopes a client may request for a resource", func(args []string) error {
		fs := flag.NewFlagSet("grant-scopes", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		cl := fs.String("client", "", "client reference (cli_...)")
		res := fs.String("resource", "", "resource ID (res_...)")
		scopes := fs.String("scopes", "", "space- or comma-separated scopes")
		subjects := fs.String("subjects", "user", "comma-separated subject types (user, service_principal)")
		_ = fs.Parse(args)
		if *cl == "" || *res == "" {
			return errors.New("--client and --resource are required")
		}
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		return c.SetResourceGrant(context.Background(), *cl, *res, splitList(*scopes), splitList(*subjects))
	})
	register("sessions", "list a user's sessions, or revoke one with --revoke", func(args []string) error {
		fs := flag.NewFlagSet("sessions", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		user := fs.String("user", "", "user ID")
		revoke := fs.String("revoke", "", "session ID to revoke")
		_ = fs.Parse(args)
		if *user == "" {
			return errors.New("--user is required")
		}
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		if *revoke != "" {
			return c.RevokeSession(context.Background(), *user, *revoke)
		}
		list, err := c.UserSessions(context.Background(), *user)
		if err != nil {
			return err
		}
		for _, s := range list {
			fmt.Printf("%s  %s  %-22s %-16s %s\n", s.ID, s.LastActivityAt.Format(time.RFC3339), s.DeviceLabel, s.Network, strings.Join(s.AMR, "+"))
		}
		return nil
	})
	register("invitations", "list an organization's invitations, or revoke one with --revoke", func(args []string) error {
		fs := flag.NewFlagSet("invitations", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		org := fs.String("org", "", "organization ID")
		state := fs.String("state", "", "filter by state")
		revoke := fs.String("revoke", "", "invitation ID to revoke")
		_ = fs.Parse(args)
		if *org == "" {
			return errors.New("--org is required")
		}
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		if *revoke != "" {
			return c.RevokeInvitation(context.Background(), *org, *revoke)
		}
		return c.Invitations(context.Background(), *org, *state, func(i admin.Invitation) error {
			fmt.Printf("%s  %-20s %-18s %-20s %s\n", i.ID, i.State, i.DeliveryState, i.TargetEmail, i.ExpiresAt.Format(time.RFC3339))
			return nil
		})
	})
	register("support-grants", "list support (impersonation) grants, or revoke one with --revoke", func(args []string) error {
		fs := flag.NewFlagSet("support-grants", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		state := fs.String("state", "active", "filter by state")
		org := fs.String("org", "", "filter by organization ID")
		revoke := fs.String("revoke", "", "grant ID to revoke")
		reason := fs.String("reason", "", "revocation reason")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		if *revoke != "" {
			return c.RevokeImpersonation(context.Background(), *revoke, *reason)
		}
		list, err := c.ImpersonationGrants(context.Background(), url.Values{"state": {*state}, "organization_id": {*org}})
		if err != nil {
			return err
		}
		for _, g := range list {
			fmt.Printf("%s  actor=%s target=%s org=%s %s %s until %s\n", g.ID, g.ActorUserID, g.TargetUserID, g.OrganizationID, g.Mode, g.State,
				g.ExpiresAt.Format(time.RFC3339))
		}
		return nil
	})
	register("permissions", "explain a subject's effective permissions with provenance", func(args []string) error {
		fs := flag.NewFlagSet("permissions", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		subject := fs.String("subject", "", "user or service principal ID")
		org := fs.String("org", "", "organization ID (default: realm scope)")
		_ = fs.Parse(args)
		if *subject == "" {
			return errors.New("--subject is required")
		}
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		ex, err := c.SubjectPermissions(context.Background(), *subject, *org)
		if err != nil {
			return err
		}
		for _, src := range ex.Sources {
			state := "applies"
			if !src.Applies {
				state = "conditions not met"
			}
			fmt.Printf("%-12s %-24s %-20s %s\n", src.Via, src.RoleName, state, strings.Join(src.Permissions, ","))
		}
		fmt.Printf("restricting policies: %d\n", ex.RestrictingPolicies)
		return nil
	})
	register("password-calibrate", "benchmark Argon2id on this host and suggest parameters (CRED-001)", passwordCalibrate)
}

func splitList(s string) []string {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// passwordCalibrate measures Argon2id cost on the deployment host and prints
// the strongest parameters that fit the target verification time and memory
// budget, never below the production floor (19 MiB, t=2).
func passwordCalibrate(args []string) error {
	fs := flag.NewFlagSet("password-calibrate", flag.ExitOnError)
	target := fs.Duration("target", 250*time.Millisecond, "target time for one verification")
	maxMem := fs.Int("max-memory-mib", 256, "largest memory cost to consider, in MiB")
	threads := fs.Int("threads", 1, "parallelism (keep low on shared hosts)")
	concurrency := fs.Int("concurrency", 8, "expected concurrent verifications per instance (memory headroom check)")
	_ = fs.Parse(args)
	if *threads < 1 || *threads > 16 || *maxMem < 19 || *maxMem > 4096 {
		return errors.New("threads must be 1..16 and max-memory-mib 19..4096")
	}
	measure := func(memKiB, t uint32) time.Duration {
		salt := []byte("proudauth-calibration")
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			argon2.IDKey([]byte("calibration password value"), salt, t, memKiB, uint8(*threads), 32)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	fmt.Printf("host: %d CPUs, threads=%d, target=%s\n\n%-10s %-4s %s\n", runtime.NumCPU(), *threads, *target, "memory", "t", "time")
	type choice struct {
		mem, t uint32
		d      time.Duration
	}
	var best *choice
	for mib := 19; mib <= *maxMem; mib *= 2 {
		mem := uint32(mib) * 1024
		for t := uint32(2); t <= 6; t++ {
			d := measure(mem, t)
			fmt.Printf("%-10s %-4d %s\n", fmt.Sprintf("%dMiB", mib), t, d.Round(time.Millisecond))
			if d > *target {
				break
			}
			if best == nil || uint64(mem)*uint64(t) > uint64(best.mem)*uint64(best.t) {
				best = &choice{mem, t, d}
			}
		}
	}
	if best == nil {
		fmt.Println("\nno parameter set met the target; the production floor (19456 KiB, t=2) is still required — add CPU or raise the target")
		return nil
	}
	fmt.Printf("\nsuggested configuration (%s per verification):\n\nsecurity:\n  password:\n    argon_memory_kib: %d\n    argon_time: %d\n    argon_threads: %d\n",
		best.d.Round(time.Millisecond), best.mem, best.t, *threads)
	fmt.Printf("\npeak memory for %d concurrent verifications: %d MiB — keep it well under the instance limit.\n",
		*concurrency, int(best.mem)/1024*(*concurrency))
	fmt.Println("Existing verifiers are rehashed with the new parameters at each user's next successful sign-in (CRED-004).")
	return nil
}
