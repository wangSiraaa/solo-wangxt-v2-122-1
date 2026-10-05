// Package zone implements the in-memory authoritative zone model:
// parsing RFC 1035 zone text, semantic validation (record-type allow-list,
// TTL bounds, CNAME conflicts, in-zone owners), immutable snapshots and
// diffing between two versions for IXFR/changelog generation.
package zone

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Record types this server explicitly supports. Anything else appearing
// in a zone file (including DNSSEC types like RRSIG/NSEC/DNSKEY) is rejected.
var allowedTypes = map[uint16]bool{
	dns.TypeSOA:   true,
	dns.TypeNS:    true,
	dns.TypeA:     true,
	dns.TypeAAAA:  true,
	dns.TypeCNAME: true,
	dns.TypeMX:    true,
	dns.TypeTXT:   true,
	dns.TypeSRV:   true,
	dns.TypePTR:   true,
	dns.TypeCAA:   true,
}

// IsAllowedType reports whether t is on the supported record-type list.
func IsAllowedType(t uint16) bool { return allowedTypes[t] }

// Limits configures the accepted TTL window for zone records.
type Limits struct {
	MinTTL uint32
	MaxTTL uint32
}

// Snapshot is an immutable point-in-time copy of a zone version.
// All lookups operate on snapshots, so a query can never observe a
// half-published version: the swap to a new snapshot is a single
// pointer assignment.
type Snapshot struct {
	Origin   string
	Serial   uint32
	RRs      []dns.RR // full canonical RRset, SOA/NS(apex) first then sorted
	byName   map[string][]dns.RR
	wildcard map[string][]dns.RR // exact wildcard label -> records ("*.lab.test.")
}

func (s *Snapshot) buildIndex() {
	s.byName = make(map[string][]dns.RR)
	s.wildcard = make(map[string][]dns.RR)
	for _, rr := range s.RRs {
		name := rr.Header().Name
		if strings.HasPrefix(name, "*.") {
			s.wildcard[name] = append(s.wildcard[name], rr)
			continue
		}
		s.byName[name] = append(s.byName[name], rr)
	}
}

// Lookup returns all records at name of the given qtype, following up to
// eight CNAME hops, along with the records in traversal order. qtype TypeANY
// returns every record at the name. Wildcards (RFC 4592) are consulted.
// The returned found flag distinguishes NXDOMAIN (name does not exist)
// from NODATA (name exists, no record of the requested type).
func (s *Snapshot) Lookup(qname string, qtype uint16) (answers []dns.RR, found bool) {
	name := strings.ToLower(qname)
	seen := map[string]bool{}
	for hops := 0; hops <= 8; hops++ {
		direct, directExists := s.lookupName(name)
		var rrs []dns.RR
		if directExists {
			rrs = direct
		} else if wc := s.matchWildcard(name); wc != nil {
			// Synthesize: wildcard owner becomes the queried name.
			for _, rr := range wc {
				cp := dns.Copy(rr)
				cp.Header().Name = name
				rrs = append(rrs, cp)
			}
		} else {
			return answers, found
		}
		found = true

		if qtype == dns.TypeANY {
			answers = append(answers, rrs...)
			return
		}
		var matched []dns.RR
		var cname *dns.CNAME
		for _, rr := range rrs {
			if rr.Header().Rrtype == qtype {
				matched = append(matched, rr)
			}
			if c, ok := rr.(*dns.CNAME); ok {
				cname = c
			}
		}
		if len(matched) > 0 {
			answers = append(answers, matched...)
			return
		}
		if qtype == dns.TypeCNAME || cname == nil || seen[name] {
			return
		}
		seen[name] = true
		answers = append(answers, cname)
		name = strings.ToLower(cname.Target)
		if !dns.IsSubDomain(s.Origin, name) {
			// Target outside the zone; the server cannot chase it.
			return
		}
	}
	return
}

func (s *Snapshot) lookupName(name string) ([]dns.RR, bool) {
	rrs, ok := s.byName[strings.ToLower(name)]
	return rrs, ok
}

// matchWildcard implements RFC 4592 source-of-synthesis lookup: find the
// closest encloser (the deepest concrete ancestor name of qname; the
// apex always counts as concrete because it holds SOA/NS), then test
// wildcard names one label below it, nearest first.
func (s *Snapshot) matchWildcard(name string) []dns.RR {
	name = strings.ToLower(name)
	if !dns.IsSubDomain(s.Origin, name) || name == s.Origin {
		return nil
	}
	labels := dns.SplitDomainName(name)
	originN := dns.CountLabel(s.Origin)
	// strip = number of qname labels removed to reach the closest
	// encloser. labels[strip:] is the encloser suffix.
	strip := 0
	for strip < len(labels)-originN {
		suffix := strings.Join(labels[strip+1:], ".") + "."
		if _, concrete := s.lookupName(suffix); concrete {
			break
		}
		strip++
	}
	// Candidate wildcard expands qname's (strip+1)th label to "*":
	// for strip=0 -> "*.<parent>"; try deeper wildcards only while no
	// concrete name blocks them. Nearest candidate first.
	for i := strip; i >= 0; i-- {
		suffix := strings.Join(labels[i+1:], ".") + "."
		if rrs, ok := s.wildcard["*."+suffix]; ok {
			return rrs
		}
	}
	return nil
}

// SOA returns the zone SOA record (a copy), or nil if absent.
func (s *Snapshot) SOA() *dns.SOA {
	for _, rr := range s.RRs {
		if soa, ok := rr.(*dns.SOA); ok {
			return dns.Copy(soa).(*dns.SOA)
		}
	}
	return nil
}

// NegativeTTL returns the TTL to put on the SOA in negative responses:
// min(SOA TTL, SOA minimum field) per RFC 2308 section 5.
func (s *Snapshot) NegativeTTL() uint32 {
	soa := s.SOA()
	if soa == nil {
		return 0
	}
	if soa.Hdr.Ttl < soa.Minttl {
		return soa.Hdr.Ttl
	}
	return soa.Minttl
}

// Parse reads an RFC 1035 master file and returns the RRs normalized to the
// given origin. TTL values are checked against lim but the serial in the
// SOA is left untouched (the caller rewrites it on publish).
func Parse(r io.Reader, origin string, lim Limits) ([]dns.RR, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(origin), "input")
	var out []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := validateRR(rr, dns.Fqdn(origin), lim); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("zone parse: %w", err)
	}
	if err := validateSet(out, dns.Fqdn(origin)); err != nil {
		return nil, err
	}
	sortRRs(out, dns.Fqdn(origin))
	return out, nil
}

// NewSnapshot builds an immutable snapshot with a store-assigned serial.
func NewSnapshot(origin string, serial uint32, rrs []dns.RR) (*Snapshot, error) {
	return newSnapshot(origin, serial, rrs, true)
}

// NewCandidateSnapshot builds a validated snapshot for a file being checked
// without rewriting the SOA serial. It is used by publish previews.
func NewCandidateSnapshot(origin string, rrs []dns.RR) (*Snapshot, error) {
	return newSnapshot(origin, 0, rrs, false)
}

func newSnapshot(origin string, serial uint32, rrs []dns.RR, rewriteSerial bool) (*Snapshot, error) {
	origin = dns.Fqdn(origin)
	for _, rr := range rrs {
		if err := validateRR(rr, origin, Limits{MinTTL: 0, MaxTTL: ^uint32(0)}); err != nil {
			return nil, err
		}
	}
	if err := validateSet(rrs, origin); err != nil {
		return nil, err
	}
	cp := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := dns.Copy(rr)
		if rewriteSerial {
			if soa, ok := c.(*dns.SOA); ok {
				soa.Serial = serial
			}
		}
		cp[i] = c
	}
	sortRRs(cp, origin)
	snapshotSerial := serial
	if !rewriteSerial {
		for _, rr := range cp {
			if soa, ok := rr.(*dns.SOA); ok {
				snapshotSerial = soa.Serial
				break
			}
		}
	}
	s := &Snapshot{Origin: origin, Serial: snapshotSerial, RRs: cp}
	s.buildIndex()
	return s, nil
}

func validateRR(rr dns.RR, origin string, lim Limits) error {
	h := rr.Header()
	if h.Class != dns.ClassINET {
		return fmt.Errorf("record %s %s: only class IN supported", h.Name, dns.TypeToString[h.Rrtype])
	}
	if !allowedTypes[h.Rrtype] {
		return fmt.Errorf("record %s %s: type not supported by this server", h.Name, dns.TypeToString[h.Rrtype])
	}
	if h.Ttl < lim.MinTTL {
		return fmt.Errorf("record %s %s: TTL %d below minimum %d", h.Name, dns.TypeToString[h.Rrtype], h.Ttl, lim.MinTTL)
	}
	if h.Ttl > lim.MaxTTL {
		return fmt.Errorf("record %s %s: TTL %d above maximum %d", h.Name, dns.TypeToString[h.Rrtype], h.Ttl, lim.MaxTTL)
	}
	name := strings.ToLower(h.Name)
	if !dns.IsSubDomain(origin, name) {
		return fmt.Errorf("record %s %s: owner name outside zone %s", h.Name, dns.TypeToString[h.Rrtype], origin)
	}
	if h.Rrtype == dns.TypeNS && name != origin {
		return fmt.Errorf("NS record %s: only apex NS is supported in this zone", h.Name)
	}
	return nil
}

// validateSet enforces whole-zone invariants:
// exactly one SOA at apex, apex CNAME forbidden, and the RFC 1034 CNAME
// coexistence rule (a CNAME owner may have no other record type, and a
// name with other records may not gain a CNAME).
func validateSet(rrs []dns.RR, origin string) error {
	soaCount := 0
	nsAtApex := 0
	byName := map[string]map[uint16]int{}
	for _, rr := range rrs {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if name == origin {
			switch h.Rrtype {
			case dns.TypeSOA:
				soaCount++
			case dns.TypeNS:
				nsAtApex++
			}
		}
		if _, ok := byName[name]; !ok {
			byName[name] = map[uint16]int{}
		}
		byName[name][h.Rrtype]++
	}
	if soaCount != 1 {
		return fmt.Errorf("zone must contain exactly one SOA record at apex %s, found %d", origin, soaCount)
	}
	if nsAtApex == 0 {
		return fmt.Errorf("zone must contain at least one NS record at apex %s", origin)
	}
	for name, types := range byName {
		if _, hasCNAME := types[dns.TypeCNAME]; hasCNAME {
			if name == origin {
				return errors.New("CNAME at zone apex is forbidden (apex must keep SOA and NS)")
			}
			if types[dns.TypeCNAME] > 1 {
				return fmt.Errorf("multiple CNAME records at %s", name)
			}
			if len(types) > 1 {
				return fmt.Errorf("CNAME at %s conflicts with other record type(s) at the same name (RFC 1034)", name)
			}
		}
	}
	return nil
}

// Key identifies a resource record independently of its TTL: same owner,
// type and rdata body. Used for diffs.
func rrKey(rr dns.RR) string {
	h := rr.Header()
	return strings.ToLower(h.Name) + "|" + dns.TypeToString[h.Rrtype] + "|" + canonicalRdata(rr)
}

// canonicalRdata renders rdata without the owner/TTL/class/type prefix.
func canonicalRdata(rr dns.RR) string {
	// miekg format: "name\tttl\tclass\ttype\trdata..." (5+ tab fields).
	parts := strings.Split(rr.String(), "\t")
	if len(parts) >= 5 {
		return strings.ToLower(strings.Join(parts[4:], " "))
	}
	return strings.ToLower(rr.String())
}

// Change is one removed or added record between two zone versions.
type Change struct {
	Action string // "ADD" or "DEL"
	RR     dns.RR
}

// ChangeKind classifies a semantic record difference.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeDeleted ChangeKind = "deleted"
	ChangeTTL     ChangeKind = "ttl_changed"
	ChangeContent ChangeKind = "content_changed"
)

// RecordChange is a stable, machine-readable description of one semantic
// difference between two snapshots. TTL and rdata changes each expand to
// one DEL plus one ADD in the stored/IXFR change log.
type RecordChange struct {
	Kind   ChangeKind `json:"kind"`
	Name   string     `json:"name"`
	Type   string     `json:"type"`
	OldRR  string     `json:"old_rr,omitempty"`
	NewRR  string     `json:"new_rr,omitempty"`
	OldTTL uint32     `json:"old_ttl,omitempty"`
	NewTTL uint32     `json:"new_ttl,omitempty"`
}

// DiffReport contains both the semantic preview of a difference and the
// ADD/DEL operations used by the published change log and IXFR.
type DiffReport struct {
	RecordChanges []RecordChange   `json:"record_changes"`
	ChangeLog     []ChangeLogEntry `json:"change_log"`
	AffectedNames []string         `json:"affected_names"`
	Operations    []Change         `json:"-"`
}

// ChangeLogEntry is one machine-readable ADD/DEL operation in the same order
// as the stored version change log.
type ChangeLogEntry struct {
	Action string `json:"action"`
	RR     string `json:"rr"`
}

// Compare returns the semantic difference and corresponding ADD/DEL
// operations from old to new. The apex SOA is excluded: its serial changes
// with every version and is carried structurally by zone versions / the
// IXFR envelope.
//
// Records are compared as multisets keyed by owner, type and rdata. A TTL
// change is therefore reported as one ttl_changed record and emits DEL(old
// TTL)+ADD(new TTL), preserving the change-log behavior used by caches and
// IXFR clients.
func Compare(old, new *Snapshot) DiffReport {
	oldGroups := groupRecords(nonSOA(old))
	newGroups := groupRecords(nonSOA(new))
	keys := make([]groupKey, 0, len(oldGroups)+len(newGroups))
	for k := range oldGroups {
		keys = append(keys, k)
	}
	for k := range newGroups {
		if _, ok := oldGroups[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owner != keys[j].owner {
			return keys[i].owner < keys[j].owner
		}
		return keys[i].rrtype < keys[j].rrtype
	})

	var report DiffReport
	for _, group := range keys {
		oldRemaining := append([]dns.RR(nil), oldGroups[group]...)
		newRemaining := append([]dns.RR(nil), newGroups[group]...)

		// Exact matches (same rdata and TTL) are unchanged records.
		oldByFull, newByFull := fullRecordMap(oldRemaining), fullRecordMap(newRemaining)
		for fk := range oldByFull {
			if common := min(len(oldByFull[fk]), len(newByFull[fk])); common > 0 {
				oldRemaining = removeFull(oldRemaining, fk, common)
				newRemaining = removeFull(newRemaining, fk, common)
			}
		}

		// Remaining entries with the same rdata differ only in TTL. Sort both
		// TTL variants so the pairing is deterministic when duplicate records
		// use several different TTLs.
		oldByContent, newByContent := contentRecordMap(oldRemaining), contentRecordMap(newRemaining)
		contentKeys := make([]string, 0)
		for rdata := range oldByContent {
			if _, ok := newByContent[rdata]; ok {
				contentKeys = append(contentKeys, rdata)
			}
		}
		sort.Strings(contentKeys)
		for _, rdata := range contentKeys {
			os := sortedRRs(oldByContent[rdata])
			ns := sortedRRs(newByContent[rdata])
			common := min(len(os), len(ns))
			for i := 0; i < common; i++ {
				addRecordChange(&report, ChangeTTL, os[i], ns[i])
			}
			oldRemaining = removeContent(oldRemaining, rdata, common)
			newRemaining = removeContent(newRemaining, rdata, common)
		}

		// Any balanced old/new remainder at this owner/type is an rdata
		// replacement; an unbalanced count leaves explicit adds/deletes.
		oldRemaining = sortedRRs(oldRemaining)
		newRemaining = sortedRRs(newRemaining)
		contentPairs := min(len(oldRemaining), len(newRemaining))
		for i := 0; i < contentPairs; i++ {
			addRecordChange(&report, ChangeContent, oldRemaining[i], newRemaining[i])
		}
		for i := contentPairs; i < len(oldRemaining); i++ {
			addRecordChange(&report, ChangeDeleted, oldRemaining[i], nil)
		}
		for i := contentPairs; i < len(newRemaining); i++ {
			addRecordChange(&report, ChangeAdded, nil, newRemaining[i])
		}
	}

	sortRecordChanges(report.RecordChanges)
	report.Operations = operations(report.RecordChanges)
	sortChanges(report.Operations)
	report.ChangeLog = make([]ChangeLogEntry, 0, len(report.Operations))
	for _, change := range report.Operations {
		report.ChangeLog = append(report.ChangeLog, ChangeLogEntry{
			Action: change.Action,
			RR:     CanonicalText(change.RR),
		})
	}
	report.AffectedNames = affectedNames(report.RecordChanges)
	if report.RecordChanges == nil {
		report.RecordChanges = []RecordChange{}
	}
	if report.AffectedNames == nil {
		report.AffectedNames = []string{}
	}
	return report
}

type groupKey struct {
	owner  string
	rrtype string
}

type fullRecordKey struct {
	rdata string
	ttl   uint32
}

func groupRecords(rrs []dns.RR) map[groupKey][]dns.RR {
	out := map[groupKey][]dns.RR{}
	for _, rr := range rrs {
		h := rr.Header()
		k := groupKey{owner: strings.ToLower(h.Name), rrtype: dns.TypeToString[h.Rrtype]}
		out[k] = append(out[k], rr)
	}
	return out
}

func fullRecordMap(rrs []dns.RR) map[fullRecordKey][]dns.RR {
	out := map[fullRecordKey][]dns.RR{}
	for _, rr := range rrs {
		k := fullRecordKey{rdata: canonicalRdata(rr), ttl: rr.Header().Ttl}
		out[k] = append(out[k], rr)
	}
	return out
}

func contentRecordMap(rrs []dns.RR) map[string][]dns.RR {
	out := map[string][]dns.RR{}
	for _, rr := range rrs {
		k := canonicalRdata(rr)
		out[k] = append(out[k], rr)
	}
	return out
}

func removeFull(rrs []dns.RR, k fullRecordKey, n int) []dns.RR {
	return removeMatching(rrs, n, func(rr dns.RR) bool {
		return canonicalRdata(rr) == k.rdata && rr.Header().Ttl == k.ttl
	})
}

func removeContent(rrs []dns.RR, rdata string, n int) []dns.RR {
	return removeMatching(rrs, n, func(rr dns.RR) bool {
		return canonicalRdata(rr) == rdata
	})
}

func removeMatching(rrs []dns.RR, n int, match func(dns.RR) bool) []dns.RR {
	out := rrs[:0]
	removed := 0
	for _, rr := range rrs {
		if removed < n && match(rr) {
			removed++
			continue
		}
		out = append(out, rr)
	}
	return out
}

func sortedRRs(rrs []dns.RR) []dns.RR {
	sort.SliceStable(rrs, func(i, j int) bool {
		if rrs[i].Header().Ttl != rrs[j].Header().Ttl {
			return rrs[i].Header().Ttl < rrs[j].Header().Ttl
		}
		return canonicalRdata(rrs[i]) < canonicalRdata(rrs[j])
	})
	return rrs
}

func nonSOA(snap *Snapshot) []dns.RR {
	if snap == nil {
		return nil
	}
	out := make([]dns.RR, 0, len(snap.RRs))
	for _, rr := range snap.RRs {
		if rr.Header().Rrtype != dns.TypeSOA {
			out = append(out, rr)
		}
	}
	return out
}

func addRecordChange(report *DiffReport, kind ChangeKind, oldRR, newRR dns.RR) {
	change := RecordChange{Kind: kind}
	var rr dns.RR
	if oldRR != nil {
		rr, change.OldRR, change.OldTTL = oldRR, CanonicalText(oldRR), oldRR.Header().Ttl
	}
	if newRR != nil {
		rr, change.NewRR, change.NewTTL = newRR, CanonicalText(newRR), newRR.Header().Ttl
	}
	h := rr.Header()
	change.Name = strings.ToLower(h.Name)
	change.Type = dns.TypeToString[h.Rrtype]
	report.RecordChanges = append(report.RecordChanges, change)
}

func operations(changes []RecordChange) []Change {
	var out []Change
	for _, change := range changes {
		switch change.Kind {
		case ChangeDeleted:
			out = append(out, Change{Action: "DEL", RR: mustCanonicalRR(change.OldRR)})
		case ChangeAdded:
			out = append(out, Change{Action: "ADD", RR: mustCanonicalRR(change.NewRR)})
		case ChangeTTL, ChangeContent:
			out = append(out,
				Change{Action: "DEL", RR: mustCanonicalRR(change.OldRR)},
				Change{Action: "ADD", RR: mustCanonicalRR(change.NewRR)},
			)
		}
	}
	return out
}

func sortRecordChanges(changes []RecordChange) {
	rank := map[ChangeKind]int{
		ChangeDeleted: 0,
		ChangeTTL:     1,
		ChangeContent: 2,
		ChangeAdded:   3,
	}
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		if rank[changes[i].Kind] != rank[changes[j].Kind] {
			return rank[changes[i].Kind] < rank[changes[j].Kind]
		}
		return changes[i].OldRR+changes[i].NewRR < changes[j].OldRR+changes[j].NewRR
	})
}

func affectedNames(changes []RecordChange) []string {
	seen := map[string]bool{}
	var names []string
	for _, change := range changes {
		if !seen[change.Name] {
			seen[change.Name] = true
			names = append(names, change.Name)
		}
	}
	sort.Strings(names)
	return names
}

func mustCanonicalRR(text string) dns.RR {
	rr, err := dns.NewRR(text)
	if err != nil {
		panic(fmt.Sprintf("internal error: canonical RR %q is invalid: %v", text, err))
	}
	return rr
}

// Diff returns the DEL/ADD change log from old to new. See Compare for the
// semantic differences and SOA handling.
func Diff(old, new *Snapshot) []Change {
	return Compare(old, new).Operations
}

func sortChanges(ch []Change) {
	sort.SliceStable(ch, func(i, j int) bool {
		if ch[i].Action != ch[j].Action {
			return ch[i].Action == "DEL" // DEL before ADD
		}
		return rrKey(ch[i].RR) < rrKey(ch[j].RR)
	})
}

// sortRRs orders records deterministically: SOA first, apex NS next, then
// by name and type. This is the AXFR wire order clients expect.
func sortRRs(rrs []dns.RR, origin string) {
	rank := func(rr dns.RR) int {
		h := rr.Header()
		switch {
		case h.Rrtype == dns.TypeSOA && strings.EqualFold(h.Name, origin):
			return 0
		case h.Rrtype == dns.TypeNS && strings.EqualFold(h.Name, origin):
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(rrs, func(i, j int) bool {
		ri, rj := rank(rrs[i]), rank(rrs[j])
		if ri != rj {
			return ri < rj
		}
		ni := strings.ToLower(rrs[i].Header().Name)
		nj := strings.ToLower(rrs[j].Header().Name)
		if ni != nj {
			return ni < nj
		}
		if rrs[i].Header().Rrtype != rrs[j].Header().Rrtype {
			return rrs[i].Header().Rrtype < rrs[j].Header().Rrtype
		}
		return canonicalRdata(rrs[i]) < canonicalRdata(rrs[j])
	})
}

// CanonicalText serializes an RR in stable master-file form for storage.
func CanonicalText(rr dns.RR) string {
	h := rr.Header()
	return fmt.Sprintf("%s %d IN %s %s",
		strings.ToLower(h.Name),
		h.Ttl,
		dns.TypeToString[h.Rrtype],
		canonicalRdata(rr))
}
