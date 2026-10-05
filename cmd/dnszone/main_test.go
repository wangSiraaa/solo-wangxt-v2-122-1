package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePreviewFixture(t *testing.T, zoneText string) (cfgPath, zonePath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.json")
	zonePath = filepath.Join(dir, "zone.db")
	configJSON := `{
  "zone": "lab.test.",
  "listen_udp": "127.0.0.1:0",
  "listen_tcp": "127.0.0.1:0",
  "database_url": "postgres://invalid.invalid/dnszone?sslmode=disable&connect_timeout=1",
  "ttl_min": 30,
  "ttl_max": 86400
}
`
	if err := os.WriteFile(cfgPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zonePath, []byte(zoneText), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, zonePath
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fnErr := fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	output, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), fnErr
}

func TestPreviewJSONReportsValidationFailures(t *testing.T) {
	cases := map[string]struct {
		zoneText string
		want     string
	}{
		"illegal TTL": {
			zoneText: `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
low 5 IN A 127.0.0.1
`,
			want: "TTL 5 below minimum 30",
		},
		"CNAME conflict": {
			zoneText: `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
www IN A 127.0.0.20
www IN CNAME other.lab.test.
`,
			want: "CNAME at www.lab.test. conflicts",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfgPath, zonePath := writePreviewFixture(t, tc.zoneText)
			output, err := captureStdout(t, func() error {
				return runPublish([]string{
					"-config", cfgPath,
					"-file", zonePath,
					"--preview", "--json",
				})
			})
			var exitErr *exitCodeError
			if !errors.As(err, &exitErr) || exitErr.code != 1 {
				t.Fatalf("runPublish err=%v, want exit code 1", err)
			}
			var out previewOutput
			if err := json.Unmarshal([]byte(output), &out); err != nil {
				t.Fatalf("preview JSON %q: %v", output, err)
			}
			if out.Valid {
				t.Fatal("invalid candidate preview reported valid")
			}
			if !strings.Contains(out.ValidationIssue, tc.want) {
				t.Fatalf("validation issue = %q, want %q", out.ValidationIssue, tc.want)
			}
		})
	}
}

func TestJSONRequiresPreview(t *testing.T) {
	cfgPath, zonePath := writePreviewFixture(t, "")
	err := runPublish([]string{
		"-config", cfgPath,
		"-file", zonePath,
		"--json",
	})
	if err == nil || !strings.Contains(err.Error(), "--preview") {
		t.Fatalf("err=%v, want --json requires --preview", err)
	}
}
