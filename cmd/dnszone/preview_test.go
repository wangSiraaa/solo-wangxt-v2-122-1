package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatalf("bad fixture RR %q: %v", text, err)
	}
	return rr
}

func sampleView(t *testing.T) *previewResultView {
	add := mustRR(t, "host2.lab.test. 3600 IN A 127.0.0.30")
	del := mustRR(t, "gone.lab.test. 3600 IN TXT \"removed\"")
	oldTTL := mustRR(t, "ns1.lab.test. 3600 IN A 127.0.0.10")
	newTTL := mustRR(t, "ns1.lab.test. 7200 IN A 127.0.0.10")
	oldRdata := mustRR(t, "www.lab.test. 3600 IN A 127.0.0.21")
	newRdata := mustRR(t, "www.lab.test. 3600 IN A 127.0.0.22")
	return &previewResultView{
		currentSerial:  1,
		nextSerial:     2,
		candidateCount: 22,
		currentCount:   21,
		recordChanges: []zone.RecordChange{
			{Kind: zone.RecordDeleted, Name: "gone.lab.test.", Type: dns.TypeTXT, OldRR: del},
			{Kind: zone.RecordAdded, Name: "host2.lab.test.", Type: dns.TypeA, NewRR: add},
			{Kind: zone.RecordContentChanged, Name: "www.lab.test.", Type: dns.TypeA,
				OldRR: oldRdata, NewRR: newRdata},
			{Kind: zone.RecordTTLChanged, Name: "ns1.lab.test.", Type: dns.TypeA,
				OldRR: oldTTL, NewRR: newTTL},
		},
		changes: []zone.Change{
			{Action: "DEL", RR: oldRdata},
			{Action: "DEL", RR: del},
			{Action: "ADD", RR: add},
			{Action: "DEL", RR: oldTTL},
			{Action: "ADD", RR: newTTL},
			{Action: "ADD", RR: newRdata},
		},
		affectedNames: []string{"gone.lab.test.", "host2.lab.test.",
			"ns1.lab.test.", "www.lab.test."},
	}
}

func TestJSONPreviewReportIsValidAndComplete(t *testing.T) {
	rep := buildPreviewReport("zone.db", "lab.test.", sampleView(t), nil)
	var buf bytes.Buffer
	if err := writeJSONPreview(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var got previewReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if !got.Valid || got.Mode != "preview" || got.Zone != "lab.test." {
		t.Fatalf("report header wrong: %+v", got)
	}
	if got.CurrentSerial != 1 || got.NextSerial != 2 {
		t.Fatalf("serials = %d/%d", got.CurrentSerial, got.NextSerial)
	}
	if got.ChangeSummary[zone.RecordAdded] != 1 ||
		got.ChangeSummary[zone.RecordDeleted] != 1 ||
		got.ChangeSummary[zone.RecordContentChanged] != 1 ||
		got.ChangeSummary[zone.RecordTTLChanged] != 1 {
		t.Fatalf("summary = %+v", got.ChangeSummary)
	}
	if len(got.RecordChanges) != 4 {
		t.Fatalf("record_changes = %d", len(got.RecordChanges))
	}
	var ttlChange *jsonRecordChange
	for i := range got.RecordChanges {
		if got.RecordChanges[i].Kind == zone.RecordTTLChanged {
			ttlChange = &got.RecordChanges[i]
		}
	}
	if ttlChange == nil || ttlChange.Old == nil || ttlChange.New == nil ||
		ttlChange.Old.TTL != 3600 || ttlChange.New.TTL != 7200 {
		t.Fatalf("TTL change rendered wrong: %+v", ttlChange)
	}
	// The exact publish changelog must be present for scripted comparison.
	if len(got.Changelog) != 6 || got.Changelog[0].Action != "DEL" {
		t.Fatalf("changelog = %+v", got.Changelog)
	}
	if len(got.AffectedNames) != 4 || got.AffectedNames[0] != "gone.lab.test." {
		t.Fatalf("affected_names = %+v", got.AffectedNames)
	}
}

func TestJSONPreviewInvalidCandidateCarriesIssues(t *testing.T) {
	rep := buildPreviewReport("bad.db", "lab.test.", nil,
		[]string{`record low.lab.test. A: TTL 5 below minimum 30`})
	var buf bytes.Buffer
	if err := writeJSONPreview(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var got previewReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Valid {
		t.Fatal("valid must be false")
	}
	if len(got.Issues) != 1 || !strings.Contains(got.Issues[0], "TTL 5 below minimum 30") {
		t.Fatalf("issues = %+v", got.Issues)
	}
	// Empty collections are [], never null, so jq consumers see arrays.
	if got.RecordChanges == nil || got.Changelog == nil || got.AffectedNames == nil {
		t.Fatalf("empty slices must marshal as []: %s", buf.String())
	}
}

func TestTextPreviewShowsAllChangeKinds(t *testing.T) {
	rep := buildPreviewReport("zone.db", "lab.test.", sampleView(t), nil)
	var buf bytes.Buffer
	writeTextPreview(&buf, rep)
	out := buf.String()
	for _, want := range []string{
		"PREVIEW of zone.db",
		"projected serial on publish: 2",
		"ADD", "DEL", "MODIFY", "TTL",
		"www.lab.test. A",
		"3600 -> 7200",
		"127.0.0.21", "127.0.0.22",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("text preview missing %q in:\n%s", want, out)
		}
	}
}

func TestTextPreviewNoChanges(t *testing.T) {
	rep := buildPreviewReport("same.db", "lab.test.",
		&previewResultView{currentSerial: 3, nextSerial: 4,
			currentCount: 20, candidateCount: 20}, nil)
	var buf bytes.Buffer
	writeTextPreview(&buf, rep)
	if !strings.Contains(buf.String(), "record changes: none") {
		t.Fatalf("want no-changes message, got:\n%s", buf.String())
	}
}

func TestTextPreviewFailureGivesReason(t *testing.T) {
	rep := buildPreviewReport("bad.db", "lab.test.", nil,
		[]string{"CNAME at www.lab.test. conflicts with other record type(s) (RFC 1034)"})
	var buf bytes.Buffer
	writeTextPreview(&buf, rep)
	out := buf.String()
	if !strings.Contains(out, "PREVIEW FAILED") ||
		!strings.Contains(out, "CNAME") ||
		strings.Contains(out, "projected serial") {
		t.Fatalf("failure text wrong:\n%s", out)
	}
}

func TestEmitPreviewExitSemantics(t *testing.T) {
	good := buildPreviewReport("zone.db", "lab.test.", sampleView(t), nil)
	var buf bytes.Buffer
	if err := writeJSONPreview(&buf, good); err != nil {
		t.Fatal(err)
	}
	// Valid preview: emitPreview returns nil (exit 0).
	if err := emitPreview("json", good); err != nil {
		t.Fatalf("valid preview must not error, got %v", err)
	}
	// Invalid preview: report emitted then errSilent for exit code 1.
	bad := buildPreviewReport("bad.db", "lab.test.", nil, []string{"x"})
	if err := emitPreview("json", bad); err == nil {
		t.Fatal("invalid preview must return a non-nil error")
	}
}
