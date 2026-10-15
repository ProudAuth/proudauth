package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/proudauth/proudauth-sdk-go/admin"
)

// Declarative configuration (SDK-012): export a realm's configuration as a
// versioned document, review the plan for a document (what it creates,
// updates, and where the realm has drifted from it), and apply it. The
// commands call the public configuration API, so the same permissions,
// recent-authentication rule and audit apply as for any API client.
func init() {
	register("config-export", "export the realm configuration document (proudauth.realm-config.v1) to a file", func(args []string) error {
		fs := flag.NewFlagSet("config-export", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		out := fs.String("o", "realm-config.json", "output file")
		wait := fs.Duration("wait", 2*time.Minute, "how long to wait for the export job")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		ctx := context.Background()
		var job struct {
			JobID string `json:"job_id"`
		}
		if _, err := c.Do(ctx, http.MethodPost, "/configuration/exports", nil, &job, admin.WithIdempotencyKey(admin.NewIdempotencyKey())); err != nil {
			return err
		}
		deadline := time.Now().Add(*wait)
		for {
			var st struct {
				State     string `json:"state"`
				LastError string `json:"last_error"`
			}
			if _, err := c.Do(ctx, http.MethodGet, "/jobs/"+job.JobID, nil, &st); err != nil {
				return err
			}
			if st.State == "succeeded" {
				break
			}
			if st.State == "failed" || st.State == "dead_letter" || st.State == "cancelled" {
				return fmt.Errorf("export job %s %s: %s", job.JobID, st.State, st.LastError)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("export job %s still %s; fetch it later with identity-cli api", job.JobID, st.State)
			}
			time.Sleep(2 * time.Second)
		}
		var dl struct {
			Token string `json:"download_token"`
		}
		if _, err := c.Do(ctx, http.MethodPost, "/jobs/"+job.JobID+"/downloads", nil, &dl); err != nil {
			return err
		}
		var doc json.RawMessage
		if _, err := c.Do(ctx, http.MethodPost, "/job-downloads", map[string]any{"download_token": dl.Token}, &doc); err != nil {
			return err
		}
		var pretty any
		if err := json.Unmarshal(doc, &pretty); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(pretty, "", "  ")
		if err := writePrivateFile(*out, append(b, '\n')); err != nil {
			return err
		}
		fmt.Printf("wrote %s (no secrets: client secrets, keys and credentials are never exported)\n", *out)
		return nil
	})
	register("config-plan", "show what applying a configuration document would change, and where the realm has drifted from it", func(args []string) error {
		fs := flag.NewFlagSet("config-plan", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		file := fs.String("f", "", "configuration document (JSON)")
		reconcile := fs.Bool("reconcile", false, "plan updates of existing clients, resources and role permissions that differ (SDK-012)")
		_ = fs.Parse(args)
		c, doc, err := configDoc(*realm, *file)
		if err != nil {
			return err
		}
		plan, err := configPlan(c, doc, *reconcile)
		if err != nil {
			return err
		}
		printPlan(plan)
		if len(plan.Errors) > 0 {
			return errors.New("the document has errors")
		}
		return nil
	})
	register("config-apply", "apply a configuration document atomically (creates missing objects; with -reconcile also updates differing ones; never deletes)", func(args []string) error {
		fs := flag.NewFlagSet("config-apply", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		file := fs.String("f", "", "configuration document (JSON)")
		reconcile := fs.Bool("reconcile", false, "also update existing clients, resources and role permissions that differ from the document (SDK-012)")
		secretsOut := fs.String("secrets-out", "", "write new client secrets to this file (mode 0600) instead of the terminal")
		yes := fs.Bool("yes", false, "apply without asking for confirmation")
		_ = fs.Parse(args)
		c, doc, err := configDoc(*realm, *file)
		if err != nil {
			return err
		}
		plan, err := configPlan(c, doc, *reconcile)
		if err != nil {
			return err
		}
		printPlan(plan)
		if len(plan.Errors) > 0 {
			return errors.New("the document has errors; nothing was applied")
		}
		if len(plan.Create) == 0 && len(plan.Update) == 0 {
			fmt.Println("nothing to apply")
			return nil
		}
		if !*yes {
			fmt.Print("apply these changes? type yes: ")
			var answer string
			_, _ = fmt.Scanln(&answer)
			if strings.TrimSpace(answer) != "yes" {
				return errors.New("not applied")
			}
		}
		var out struct {
			Applied []string                `json:"applied"`
			Secrets map[string]admin.Secret `json:"client_secrets"`
		}
		if _, err := c.Do(context.Background(), http.MethodPost, "/configuration/imports"+modeQuery(*reconcile), doc, &out); err != nil {
			return err
		}
		for _, a := range out.Applied {
			fmt.Println("applied:", a)
		}
		if len(out.Secrets) == 0 {
			return nil
		}
		plain := map[string]string{}
		for id, s := range out.Secrets {
			plain[id] = s.Reveal()
		}
		b, _ := json.MarshalIndent(plain, "", "  ")
		if *secretsOut != "" {
			if err := writePrivateFile(*secretsOut, append(b, '\n')); err != nil {
				return fmt.Errorf("the configuration was applied but the secrets could not be written: %w", err)
			}
			fmt.Printf("new client secrets written to %s; move them into your secret store and delete the file\n", *secretsOut)
			return nil
		}
		fmt.Fprintln(os.Stderr, "new client secrets (shown once; store them in your secret store, never in version control):")
		fmt.Println(string(b))
		return nil
	})
}

type cliPlan struct {
	Create    []string `json:"create"`
	Update    []string `json:"update"`
	Unchanged []string `json:"unchanged"`
	Drift     []string `json:"drift"`
	Errors    []string `json:"errors"`
	Notes     []string `json:"notes"`
}

func configDoc(realm, file string) (*admin.Client, json.RawMessage, error) {
	if file == "" {
		return nil, nil, errors.New("-f is required")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	if !json.Valid(raw) {
		return nil, nil, fmt.Errorf("%s is not valid JSON", file)
	}
	c, err := client(realm, "admin")
	return c, raw, err
}

func configPlan(c *admin.Client, doc json.RawMessage, reconcile bool) (*cliPlan, error) {
	var plan cliPlan
	_, err := c.Do(context.Background(), http.MethodPost, "/configuration/validate"+modeQuery(reconcile), doc, &plan)
	return &plan, err
}

func modeQuery(reconcile bool) string {
	if reconcile {
		return "?mode=reconcile"
	}
	return ""
}

func printPlan(p *cliPlan) {
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Printf("%s:\n", title)
		for _, it := range items {
			fmt.Printf("  %s\n", it)
		}
	}
	section("create", p.Create)
	section("update", p.Update)
	section("drift (existing objects that differ; not changed by apply)", p.Drift)
	section("errors", p.Errors)
	section("notes", p.Notes)
	fmt.Printf("%d unchanged\n", len(p.Unchanged))
}
