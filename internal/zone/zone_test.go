package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const validZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
@ IN A 127.0.0.5
www IN A 127.0.0.20
www IN A 127.0.0.21
www IN TXT "hello"
alias IN CNAME www.lab.test.
*.wild IN A 127.0.0.99
`

func mustParse(t *testing.T, text string, lim Limits) []dns.RR {
	t.Helper()
	rrs, err := Parse(strings.NewReader(text), "lab.test.", lim)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rrs
}

func TestParseValid(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, err := NewSnapshot("lab.test.", 42, rrs)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := snap.SOA().Serial; got != 42 {
		t.Fatalf("SOA serial = %d, want 42 (publisher must rewrite it)", got)
	}
}

func TestTTLBounds(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	cases := map[string]string{
		"below min": `low 29 IN A 127.0.0.1`,
		"above max": `high 90000 IN A 127.0.0.1`,
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
				rec+"\n", 1)
			if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err == nil {
				t.Fatalf("%s: expected TTL rejection", name)
			}
		})
	}
	t.Run("exact bounds accepted", func(t *testing.T) {
		text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
			"lo 30 IN A 127.0.0.1\nhi 86400 IN A 127.0.0.2\n", 1)
		if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err != nil {
			t.Fatalf("boundary TTLs rejected: %v", err)
		}
	})
}

func TestRejectCNAMEConflict(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"coexists with A": base + "h IN A 127.0.0.7\nh IN CNAME x.lab.test.\n",
		"two CNAMEs":      base + "h IN CNAME a.lab.test.\nh IN CNAME b.lab.test.\n",
		"CNAME at apex":   "@ IN CNAME elsewhere.example.net.\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected conflict rejection", name)
			}
		})
	}
}

func TestRejectOutOfZoneAndTypes(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"out of zone owner": base + "h.other.test. IN A 1.2.3.4\n",
		"unsupported type":  base + "h IN DNSKEY 256 3 8 AAAA\n",
		"class CH":          base + "h 3600 CH TXT \"x\"\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected rejection", name)
			}
		})
	}
}

func TestLookupMultiRecord(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	as, found := snap.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 2 {
		t.Fatalf("www A: found=%v n=%d, want 2 A records", found, len(as))
	}
	txts, _ := snap.Lookup("WWW.LAB.TEST.", dns.TypeTXT)
	if len(txts) != 1 {
		t.Fatalf("case-insensitive www TXT: got %d", len(txts))
	}
	// NODATA: name exists, wrong type. found stays true but no answers.
	if any, found := snap.Lookup("www.lab.test.", dns.TypeAAAA); !found || len(any) != 0 {
		t.Fatalf("www AAAA must be NODATA (found=true, 0 answers), got found=%v n=%d", found, len(any))
	}
	// NXDOMAIN: name absent.
	if _, found := snap.Lookup("missing.lab.test.", dns.TypeA); found {
		t.Fatal("missing name must report not found")
	}
}

func TestLookupCNAMEChain(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("alias.lab.test.", dns.TypeA)
	if !found || len(ans) != 3 {
		t.Fatalf("alias A: found=%v n=%d, want CNAME+2A", found, len(ans))
	}
	if ans[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatal("first answer must be the CNAME")
	}
	// Explicit CNAME query returns just the CNAME.
	cs, _ := snap.Lookup("alias.lab.test.", dns.TypeCNAME)
	if len(cs) != 1 {
		t.Fatalf("CNAME query returned %d", len(cs))
	}
}

func TestLookupWildcard(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("anything.wild.lab.test.", dns.TypeA)
	if !found || len(ans) != 1 || ans[0].Header().Name != "anything.wild.lab.test." {
		t.Fatalf("wildcard expansion wrong: found=%v ans=%v", found, ans)
	}
	if ans[0].(*dns.A).A.String() != "127.0.0.99" {
		t.Fatalf("wildcard rdata = %v", ans[0])
	}
}

func TestNegativeTTL(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if got := snap.NegativeTTL(); got != 300 {
		t.Fatalf("negative TTL = %d, want min(SOA ttl 3600, minimum 300)=300", got)
	}
}

func TestDiffExcludesSOA(t *testing.T) {
	v1 := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	s1, _ := NewSnapshot("lab.test.", 1, v1)
	v2text := strings.Replace(validZone,
		"www IN A 127.0.0.21\n",
		"www IN A 127.0.0.21\nwww IN A 127.0.0.22\n", 1)
	v2 := mustParse(t, v2text, Limits{MinTTL: 30, MaxTTL: 86400})
	s2, _ := NewSnapshot("lab.test.", 2, v2)
	changes := Diff(s1, s2)
	var n int
	for _, c := range changes {
		if c.RR.Header().Rrtype == dns.TypeSOA {
			t.Fatal("SOA must not appear in changelog deltas")
		}
		n++
	}
	if n != 1 {
		var b strings.Builder
		for _, c := range changes {
			b.WriteString(c.Action + " " + CanonicalText(c.RR) + "\n")
		}
		t.Fatalf("diff = %d changes, want 1 (only new A);\n%s", n, b.String())
	}
}

func TestAXFROrdering(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if snap.RRs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatal("AXFR must begin with SOA")
	}
	if snap.RRs[1].Header().Rrtype != dns.TypeNS {
		t.Fatalf("position 1 must be apex NS, got %v", snap.RRs[1])
	}
}

func parseSnap(t *testing.T, text string, serial uint32) *Snapshot {
	t.Helper()
	rrs, err := Parse(strings.NewReader(text), "lab.test.", Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s, err := NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return s
}

func TestDescribeGroupsContentAndTTLChanges(t *testing.T) {
	s1 := parseSnap(t, validZone, 1)
	// www A .21 -> .22 (content change), TXT rdata changes (content change),
	// ns1 A keeps rdata but TTL moves 3600 -> 7200 (TTL change), new host
	// added and alias removed.
	v2text := strings.ReplaceAll(validZone,
		`www IN A 127.0.0.21`, `www IN A 127.0.0.22`)
	v2text = strings.ReplaceAll(v2text,
		`www IN TXT "hello"`, `www IN TXT "hello v2"`)
	v2text = strings.ReplaceAll(v2text,
		"ns1 IN A 127.0.0.10", "ns1 7200 IN A 127.0.0.10")
	v2text = strings.ReplaceAll(v2text,
		`alias IN CNAME www.lab.test.`+"\n", "")
	v2text += "new IN A 127.0.0.77\n"
	s2 := parseSnap(t, v2text, 2)

	got := Describe(s1, s2)
	byKind := map[string]int{}
	type pair struct {
		name, typ, old, nw string
	}
	var pairs []pair
	for _, c := range got {
		byKind[c.Kind]++
		var oldText, newText string
		if c.OldRR != nil {
			oldText = CanonicalText(c.OldRR)
		}
		if c.NewRR != nil {
			newText = CanonicalText(c.NewRR)
		}
		pairs = append(pairs, pair{c.Name, dns.TypeToString[c.Type], oldText, newText})
	}
	if byKind[RecordAdded] != 1 || byKind[RecordDeleted] != 1 ||
		byKind[RecordContentChanged] != 2 || byKind[RecordTTLChanged] != 1 {
		t.Fatalf("Describe summary = %v, want 1 add/1 del/2 content/1 ttl", byKind)
	}
	for _, p := range pairs {
		switch {
		case p.typ == "A" && p.name == "ns1.lab.test.":
			if !strings.Contains(p.old, " 3600 IN A ") || !strings.Contains(p.nw, " 7200 IN A ") {
				t.Fatalf("TTL change must carry old/new TTL:\nold=%s\nnew=%s", p.old, p.nw)
			}
		case p.name == "new.lab.test." && p.old != "":
			t.Fatalf("added record must have no old RR: %+v", p)
		}
	}

	names := AffectedNames(got)
	want := []string{"alias.lab.test.", "new.lab.test.", "ns1.lab.test.", "www.lab.test."}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("affected names = %v, want %v", names, want)
	}
}

func TestDiffEmitsTTLChangeAsDelAndAdd(t *testing.T) {
	s1 := parseSnap(t, validZone, 1)
	v2 := strings.ReplaceAll(validZone, "ns1 IN A 127.0.0.10",
		"ns1 600 IN A 127.0.0.10")
	s2 := parseSnap(t, v2, 2)
	changes := Diff(s1, s2)
	if len(changes) != 2 {
		t.Fatalf("TTL-only change must be DEL+ADD, got %d changes", len(changes))
	}
	if changes[0].Action != "DEL" || changes[0].RR.Header().Ttl != 3600 {
		t.Fatalf("first change = %v, want DEL TTL 3600", CanonicalText(changes[0].RR))
	}
	if changes[1].Action != "ADD" || changes[1].RR.Header().Ttl != 600 {
		t.Fatalf("second change = %v, want ADD TTL 600", CanonicalText(changes[1].RR))
	}
}

func TestDescribeExpansionEqualsDiff(t *testing.T) {
	s1 := parseSnap(t, validZone, 1)
	v2 := strings.ReplaceAll(validZone,
		`www IN A 127.0.0.21`, `www IN A 127.0.0.22`)
	v2 = strings.ReplaceAll(v2, "ns1 IN A 127.0.0.10",
		"ns1 900 IN A 127.0.0.10")
	v2 += "extra IN TXT \"x\"\n"
	s2 := parseSnap(t, v2, 2)

	want := map[string]int{}
	for _, c := range Diff(s1, s2) {
		want[c.Action+" "+CanonicalText(c.RR)]++
	}
	got := map[string]int{}
	for _, c := range Describe(s1, s2) {
		switch c.Kind {
		case RecordAdded:
			got["ADD "+CanonicalText(c.NewRR)]++
		case RecordDeleted:
			got["DEL "+CanonicalText(c.OldRR)]++
		case RecordContentChanged, RecordTTLChanged:
			got["DEL "+CanonicalText(c.OldRR)]++
			got["ADD "+CanonicalText(c.NewRR)]++
		}
	}
	if len(got) != len(want) {
		t.Fatalf("Describe expansion has %d entries, Diff %d", len(got), len(want))
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("changelog mismatch at %q: describe=%d diff=%d", k, got[k], n)
		}
	}
}

func TestPureCommentChangeIsNoDiff(t *testing.T) {
	withComments := validZone + "; trailing operational comment\n"
	moreComments := strings.ReplaceAll(withComments, "@ IN NS",
		"; renamed for ticket #42\n@ IN NS")
	s1 := parseSnap(t, withComments, 1)
	s2 := parseSnap(t, moreComments, 2)
	if d := Diff(s1, s2); len(d) != 0 {
		var b strings.Builder
		for _, c := range d {
			b.WriteString(c.Action + " " + CanonicalText(c.RR) + "\n")
		}
		t.Fatalf("comment-only edit produced record diff:\n%s", b.String())
	}
	if rc := Describe(s1, s2); len(rc) != 0 {
		t.Fatalf("comment-only edit described as changes: %v", rc)
	}
	if n := AffectedNames(Describe(s1, s2)); len(n) != 0 {
		t.Fatalf("comment-only edit affected names: %v", n)
	}
}

func TestNilSnapshotPreviewStyleDiff(t *testing.T) {
	s1 := parseSnap(t, validZone, 1)
	// Nothing published yet (nil base): every non-SOA record is an addition.
	rc := Describe(nil, s1)
	for _, c := range rc {
		if c.Kind != RecordAdded || c.OldRR != nil || c.NewRR == nil {
			t.Fatalf("nil-base change %+v must be a pure addition", c)
		}
	}
	if d := Diff(nil, s1); len(d) != len(s1.RRs)-1 {
		t.Fatalf("nil base Diff = %d, want %d (SOA excluded)", len(d), len(s1.RRs)-1)
	}
}
