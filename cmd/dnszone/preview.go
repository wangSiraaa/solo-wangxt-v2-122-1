package main

// Structured and human-readable rendering for `publish -preview`.
//
// The preview report has two representations of the same data:
//
//   - record_changes groups the comparison for review (added / deleted /
//     content-changed / ttl-changed, with old/new text for the latter two);
//   - changelog is the exact ordered DEL/ADD sequence a real publish would
//     store, so scripts can assert preview output equals the post-publish
//     changelog.
//
// A failed preview still emits a JSON document (valid=false with the
// validation issues) and the process exits non-zero.

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

type jsonRR struct {
	Owner string `json:"owner"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Text  string `json:"rr"`
}

type jsonRecordChange struct {
	Kind string  `json:"kind"` // added|deleted|content-changed|ttl-changed
	Name string  `json:"name"`
	Type string  `json:"rrtype"`
	Old  *jsonRR `json:"old,omitempty"`
	New  *jsonRR `json:"new,omitempty"`
}

type jsonChangelogEntry struct {
	Action string `json:"action"` // ADD|DEL
	RR     string `json:"rr"`
}

// previewReport is the script-readable projection of a dry run. All slices
// are non-nil so empty results render as [], not null.
type previewReport struct {
	Mode           string               `json:"mode"`
	Zone           string               `json:"zone"`
	File           string               `json:"file"`
	Valid          bool                 `json:"valid"`
	CurrentSerial  uint32               `json:"current_serial"`
	NextSerial     uint32               `json:"next_serial,omitempty"`
	CandidateCount int                  `json:"candidate_record_count,omitempty"`
	CurrentCount   int                  `json:"current_record_count"`
	ChangeSummary  map[string]int       `json:"change_summary"`
	AffectedNames  []string             `json:"affected_names"`
	RecordChanges  []jsonRecordChange   `json:"record_changes"`
	Changelog      []jsonChangelogEntry `json:"changelog"`
	Issues         []string             `json:"issues"`
}

func rrToJSON(rr dns.RR) jsonRR {
	h := rr.Header()
	return jsonRR{
		Owner: h.Name,
		Type:  dns.TypeToString[h.Rrtype],
		TTL:   h.Ttl,
		Text:  zone.CanonicalText(rr),
	}
}

func buildPreviewReport(file, origin string, p *previewResultView, issues []string) previewReport {
	rep := previewReport{
		Mode:          "preview",
		Zone:          origin,
		File:          file,
		Valid:         len(issues) == 0,
		AffectedNames: []string{},
		RecordChanges: []jsonRecordChange{},
		Changelog:     []jsonChangelogEntry{},
		Issues:        []string{},
		ChangeSummary: map[string]int{
			zone.RecordAdded:          0,
			zone.RecordDeleted:        0,
			zone.RecordContentChanged: 0,
			zone.RecordTTLChanged:     0,
		},
	}
	for _, is := range issues {
		rep.Issues = append(rep.Issues, is)
	}
	if p == nil {
		return rep
	}
	rep.CurrentSerial = p.currentSerial
	rep.NextSerial = p.nextSerial
	rep.CandidateCount = p.candidateCount
	rep.CurrentCount = p.currentCount
	// Normalize nil (the zone layer's "no changes" value) to a non-nil
	// empty slice so JSON consumers always see [], never null.
	if p.affectedNames != nil {
		rep.AffectedNames = p.affectedNames
	}
	for _, c := range p.recordChanges {
		rep.ChangeSummary[c.Kind]++
		jc := jsonRecordChange{Kind: c.Kind, Name: c.Name, Type: dns.TypeToString[c.Type]}
		if c.OldRR != nil {
			old := rrToJSON(c.OldRR)
			jc.Old = &old
		}
		if c.NewRR != nil {
			nw := rrToJSON(c.NewRR)
			jc.New = &nw
		}
		rep.RecordChanges = append(rep.RecordChanges, jc)
	}
	for _, c := range p.changes {
		rep.Changelog = append(rep.Changelog,
			jsonChangelogEntry{Action: c.Action, RR: zone.CanonicalText(c.RR)})
	}
	return rep
}

// previewResultView is the store-independent slice of PreviewResult the
// renderer needs; the CLI maps store types onto it so the renderer stays
// unit-testable without a database.
type previewResultView struct {
	currentSerial  uint32
	nextSerial     uint32
	candidateCount int
	currentCount   int
	recordChanges  []zone.RecordChange
	changes        []zone.Change
	affectedNames  []string
}

func writeJSONPreview(w io.Writer, rep previewReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func writeTextPreview(w io.Writer, rep previewReport) {
	if rep.Valid {
		wr := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
		wr("PREVIEW of %s for zone %s (no changes will be made)\n", rep.File, rep.Zone)
		wr("current serial: %d  ->  projected serial on publish: %d\n",
			rep.CurrentSerial, rep.NextSerial)
		wr("records: current=%d candidate=%d\n", rep.CurrentCount, rep.CandidateCount)
		if len(rep.RecordChanges) == 0 {
			wr("record changes: none\n")
		} else {
			wr("record changes: %d added, %d deleted, %d content, %d TTL\n",
				rep.ChangeSummary[zone.RecordAdded],
				rep.ChangeSummary[zone.RecordDeleted],
				rep.ChangeSummary[zone.RecordContentChanged],
				rep.ChangeSummary[zone.RecordTTLChanged])
			wr("affected names (%d):\n", len(rep.AffectedNames))
			for _, n := range rep.AffectedNames {
				wr("  %s\n", n)
			}
			wr("details:\n")
			for _, c := range rep.RecordChanges {
				switch c.Kind {
				case zone.RecordAdded:
					wr("  ADD     %s\n", c.New.Text)
				case zone.RecordDeleted:
					wr("  DEL     %s\n", c.Old.Text)
				case zone.RecordTTLChanged:
					wr("  TTL     %s %s  %s -> %s\n",
						c.Name, c.Type, strconv.FormatUint(uint64(c.Old.TTL), 10),
						strconv.FormatUint(uint64(c.New.TTL), 10))
				case zone.RecordContentChanged:
					wr("  MODIFY  %s %s\n", c.Name, c.Type)
					wr("          - %s\n", c.Old.Text)
					wr("          + %s\n", c.New.Text)
				}
			}
		}
		if len(rep.AffectedNames) == 0 {
			wr("\ncandidate is identical to the current version " +
				"(comments and the candidate SOA serial are not record data)\n")
		}
		return
	}
	_, _ = io.WriteString(w, "PREVIEW FAILED validation for "+rep.File+"\n")
	_, _ = io.WriteString(w, "the candidate would be rejected by publish; no changes were made\n")
	for _, is := range rep.Issues {
		_, _ = io.WriteString(w, "  issue: "+is+"\n")
	}
}
