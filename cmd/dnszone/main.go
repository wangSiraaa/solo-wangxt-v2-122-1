// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve    --config config.json
//	dnszone publish  --config config.json --file zone.db [--note "..."]
//	                 [--preview] [--format text|json]
//	dnszone versions --config config.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/server"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"

	"github.com/miekg/dns"
)

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
		if !errors.Is(err, errSilent) {
			fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		}
		os.Exit(1)
	}
}

// errSilent marks an error already reported to the user (e.g. a preview
// JSON document emitted for a failed validation); main only sets the exit
// code and must not print it a second time.
var errSilent = errors.New("silent failure")

func usage() {
	fmt.Fprint(os.Stderr, `dnszone - local test-domain authoritative DNS service

Commands:
  serve     run the authoritative UDP/TCP server
  publish   atomically publish a zone file as a new version
            -preview  parse/validate and show the projected changes without
                      publishing (no serial bump, no version rows, no snapshot
                      switch); -format text (default) or json for scripts
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
	preview := fs.Bool("preview", false,
		"parse/validate with the same rules as publish and show the projected diff without publishing")
	format := fs.String("format", "text", "output format for -preview: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("-format must be text or json, got %q", *format)
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

	// Preview mode: run the same parse/validation a publish runs, compare
	// against the current version, and never write or notify. A parse
	// failure is still rendered as a structured report so automation can
	// gate on it.
	if *preview {
		return runPreview(*format, *file, cfg, lim, rrs, parseErr)
	}
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

// runPreview projects a publish without side effects and renders the
// report. It returns errSilent (after printing the report) when the
// candidate is invalid, so the process exits non-zero while the structured
// output remains the single machine-readable artifact.
func runPreview(format, file string, cfg *config.Config, lim zone.Limits,
	parsed []dns.RR, parseErr error) error {
	origin := cfg.ZoneOrigin()
	if parseErr != nil {
		// Candidate fails before the database is even touched: the running
		// service necessarily keeps serving the old records.
		rep := buildPreviewReport(file, origin, nil, []string{parseErr.Error()})
		return emitPreview(format, rep)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, origin)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	p, err := st.Preview(ctx, parsed, lim)
	if err != nil {
		// Validation defense at commit time (or a read error) rejected the
		// candidate; render it as a preview issue, identical to a parse error.
		rep := buildPreviewReport(file, origin, nil, []string{err.Error()})
		return emitPreview(format, rep)
	}

	view := &previewResultView{
		currentSerial:  p.CurrentSerial,
		nextSerial:     p.NextSerial,
		candidateCount: p.CandidateCount,
		currentCount:   p.CurrentCount,
		recordChanges:  p.RecordChanges,
		changes:        p.Changes,
		affectedNames:  p.AffectedNames,
	}
	rep := buildPreviewReport(file, origin, view, nil)
	if err := emitPreview(format, rep); err != nil {
		return err
	}
	return nil
}

// emitPreview writes the report in the requested format and returns
// errSilent for an invalid candidate so the caller exits with status 1.
func emitPreview(format string, rep previewReport) error {
	if format == "json" {
		if err := writeJSONPreview(os.Stdout, rep); err != nil {
			return err
		}
	} else {
		writeTextPreview(os.Stdout, rep)
	}
	if !rep.Valid {
		return errSilent
	}
	return nil
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
