// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve   --config config.json
//	dnszone publish --config config.json --file zone.db [--note "..."]
//	dnszone publish --preview [--json] --config config.json --file zone.db
//	dnszone versions --config config.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/server"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

type exitCodeError struct {
	code    int
	message string
	err     error
}

func (e *exitCodeError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.message
}
func (e *exitCodeError) Unwrap() error { return e.err }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "publish":
		err = runPublish(args)
	case "versions":
		err = runVersions(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			if msg := exitErr.Error(); msg != "" {
				fmt.Fprintf(os.Stderr, "%s: %s\n", cmd, msg)
			}
			os.Exit(exitErr.code)
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dnszone - local test-domain authoritative DNS service

Commands:
  serve     run the authoritative UDP/TCP server
  publish   atomically publish a zone file as a new version
            (use --preview to validate and show changes without publishing)
  versions  list published zone versions

Run "<command> -h" for command flags.
`)
}

func loadConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "dnszone ", log.LstdFlags|log.Lmicroseconds)
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	srv, err := server.New(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	file := fs.String("file", "zone.db", "RFC 1035 zone master file")
	note := fs.String("note", "", "change note stored with the version")
	preview := fs.Bool("preview", false, "validate and show the resulting diff without publishing")
	asJSON := fs.Bool("json", false, "write the preview as JSON (requires --preview)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asJSON && !*preview {
		return errors.New("--json is only supported together with --preview")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	lim := zone.Limits{MinTTL: cfg.TTLMin, MaxTTL: cfg.TTLMax}
	rrs, parseErr := zone.Parse(f, cfg.ZoneOrigin(), lim)
	if !*preview {
		if parseErr != nil {
			return parseErr
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		defer st.Close()

		res, err := st.Publish(ctx, rrs, *note, lim)
		if err != nil {
			return err
		}
		fmt.Printf("published serial %d (%d record changes)\n", res.Serial, len(res.Changes))
		for _, c := range res.Changes {
			fmt.Printf("  %s %s\n", c.Action, zone.CanonicalText(c.RR))
		}
		return nil
	}

	return runPreview(cfg, *file, rrs, parseErr, lim, *asJSON)
}

func runPreview(cfg *config.Config, file string, rrs []dns.RR, parseErr error, lim zone.Limits, asJSON bool) error {
	out := previewOutput{
		Mode:          "preview",
		Zone:          cfg.ZoneOrigin(),
		File:          file,
		RecordChanges: []zone.RecordChange{},
		ChangeLog:     []zone.ChangeLogEntry{},
		AffectedNames: []string{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, storeErr := store.NewPreview(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if storeErr == nil {
		defer st.Close()
		serial, err := st.CurrentSerial(ctx)
		if err == nil {
			out.CurrentSerial = &serial
		}
	}

	if parseErr != nil {
		out.ValidationIssue = parseErr.Error()
		return finishPreview(out, asJSON)
	}
	if storeErr != nil {
		out.ValidationIssue = fmt.Sprintf("postgres: %v", storeErr)
		return finishPreview(out, asJSON)
	}

	res, err := st.Preview(ctx, rrs, lim)
	if err != nil {
		out.ValidationIssue = err.Error()
		if out.CurrentSerial == nil {
			serial, serialErr := st.CurrentSerial(ctx)
			if serialErr == nil {
				out.CurrentSerial = &serial
			}
		}
		return finishPreview(out, asJSON)
	}

	out.Valid = true
	out.CurrentSerial = &res.CurrentSerial
	out.CandidateSOASerial = &res.CandidateSOASerial
	out.RecordChanges = res.Diff.RecordChanges
	out.ChangeLog = res.Diff.ChangeLog
	out.AffectedNames = res.Diff.AffectedNames
	return finishPreview(out, asJSON)
}

type previewOutput struct {
	Mode               string                `json:"mode"`
	Zone               string                `json:"zone"`
	File               string                `json:"file"`
	Valid              bool                  `json:"valid"`
	CurrentSerial      *uint32               `json:"current_serial"`
	CandidateSOASerial *uint32               `json:"candidate_soa_serial"`
	RecordChanges      []zone.RecordChange   `json:"record_changes"`
	ChangeLog          []zone.ChangeLogEntry `json:"change_log"`
	AffectedNames      []string              `json:"affected_names"`
	ValidationIssue    string                `json:"validation_issue,omitempty"`
}

func finishPreview(out previewOutput, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
	} else {
		printPreviewText(out)
	}
	if !out.Valid {
		if asJSON {
			return &exitCodeError{code: 1}
		}
		return &exitCodeError{code: 1, message: "preview validation failed"}
	}
	return nil
}

func printPreviewText(out previewOutput) {
	fmt.Printf("Preview for %s (%s)\n", out.Zone, out.File)
	fmt.Printf("Current serial: %s\n", serialText(out.CurrentSerial))
	fmt.Printf("Candidate SOA serial: %s\n", serialText(out.CandidateSOASerial))
	if out.Valid {
		fmt.Println("Validation: OK")
	} else {
		fmt.Printf("Validation: FAILED: %s\n", out.ValidationIssue)
	}
	if len(out.RecordChanges) == 0 {
		fmt.Println("Record changes: none")
	} else {
		fmt.Printf("Record changes: %d\n", len(out.RecordChanges))
		for _, change := range out.RecordChanges {
			switch change.Kind {
			case zone.ChangeAdded:
				fmt.Printf("  ADD     %s\n", change.NewRR)
			case zone.ChangeDeleted:
				fmt.Printf("  DELETE  %s\n", change.OldRR)
			case zone.ChangeTTL:
				fmt.Printf("  TTL     %s: %d -> %d\n", change.Name+" "+change.Type, change.OldTTL, change.NewTTL)
			case zone.ChangeContent:
				fmt.Printf("  CONTENT %s %s\n    - %s\n    + %s\n",
					change.Name, change.Type, change.OldRR, change.NewRR)
			}
		}
	}
	fmt.Printf("Affected names: %s\n", joinNames(out.AffectedNames))
	if len(out.ChangeLog) > 0 {
		fmt.Printf("Planned change log: %d operations\n", len(out.ChangeLog))
		for _, entry := range out.ChangeLog {
			fmt.Printf("  %-3s %s\n", entry.Action, entry.RR)
		}
	}
	if out.Valid {
		fmt.Println("No publication performed: SOA serial, versions and the serving snapshot are unchanged.")
	} else {
		fmt.Println("No publication performed; the current serving snapshot remains active.")
	}
}

func serialText(serial *uint32) string {
	if serial == nil {
		return "unavailable"
	}
	return fmt.Sprintf("%d", *serial)
}

func joinNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	result := ""
	for i, name := range names {
		if i > 0 {
			result += ", "
		}
		result += name
	}
	return result
}

func runVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()
	vs, err := st.ListVersions(ctx, 100)
	if err != nil {
		return err
	}
	fmt.Printf("current zone: %s\n", cfg.ZoneOrigin())
	for _, v := range vs {
		fmt.Printf("  serial %d  %s  %q\n", v.Serial,
			v.PublishedAt.Format("2006-01-02 15:04:05 MST"), v.Note)
	}
	return nil
}
