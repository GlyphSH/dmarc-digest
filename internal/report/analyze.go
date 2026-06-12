package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Verdict string

const (
	VerdictOK         Verdict = "ok"
	VerdictThirdParty Verdict = "third-party"
	VerdictSpoof      Verdict = "suspected-spoofing"
)

func (v Verdict) rank() int {
	switch v {
	case VerdictSpoof:
		return 2
	case VerdictThirdParty:
		return 1
	default:
		return 0
	}
}

// Source aggregates every record seen for one sending IP.
type Source struct {
	IP       string  `json:"ip"`
	PTR      string  `json:"ptr,omitempty"`
	Messages int     `json:"messages"`
	Passed   int     `json:"passed"`
	SPF      string  `json:"spf"`
	DKIM     string  `json:"dkim"`
	Verdict  Verdict `json:"verdict"`
	Note     string  `json:"note,omitempty"`
}

type Advice struct {
	Level string `json:"level"` // "crit", "warn", or "ok"
	Text  string `json:"text"`
}

type Summary struct {
	Reports   int               `json:"reports"`
	Domains   []string          `json:"domains"`
	Reporters []string          `json:"reporters"`
	Begin     time.Time         `json:"begin"`
	End       time.Time         `json:"end"`
	Messages  int               `json:"messages"`
	Passed    int               `json:"passed"`
	Policies  map[string]string `json:"policies"`
	Sources   []*Source         `json:"sources"`
	Advice    []Advice          `json:"advice"`
}

// ExitCode maps the summary onto CI-friendly exit codes:
// 0 all clean, 1 alignment problems only, 2 suspected spoofing.
func (s *Summary) ExitCode() int {
	worst := 0
	for _, src := range s.Sources {
		if r := src.Verdict.rank(); r > worst {
			worst = r
		}
	}
	return worst
}

// classify decides what one record means. policy_evaluated holds the *aligned*
// results, so a DMARC pass is either of them passing. When both fail, raw
// auth_results separate a misaligned-but-real sender from a spoofer.
func classify(rec Record) (Verdict, string) {
	pe := rec.Row.PolicyEvaluated
	if pe.DKIM == "pass" || pe.SPF == "pass" {
		return VerdictOK, ""
	}
	var passes []string
	for _, a := range rec.AuthResults.SPF {
		if a.Result == "pass" && a.Domain != "" {
			passes = append(passes, "SPF for "+a.Domain)
		}
	}
	for _, a := range rec.AuthResults.DKIM {
		if a.Result == "pass" && a.Domain != "" {
			passes = append(passes, "DKIM for "+a.Domain)
		}
	}
	if len(passes) > 0 {
		return VerdictThirdParty, "passes " + strings.Join(passes, ", ") + " (unaligned)"
	}
	return VerdictSpoof, "no valid SPF or DKIM"
}

type srcAgg struct {
	src      *Source
	spfPass  int
	dkimPass int
}

// Summarize merges any number of parsed reports into one digest.
func Summarize(fbs []*Feedback) *Summary {
	s := &Summary{Reports: len(fbs), Policies: map[string]string{}}
	domains := map[string]bool{}
	reporters := map[string]bool{}
	aggs := map[string]*srcAgg{}

	for _, fb := range fbs {
		if fb.Policy.Domain != "" {
			domains[fb.Policy.Domain] = true
			s.Policies[fb.Policy.Domain] = fb.Policy.Policy
		}
		if fb.Metadata.OrgName != "" {
			reporters[fb.Metadata.OrgName] = true
		}
		if b := time.Unix(fb.Metadata.DateRange.Begin, 0).UTC(); fb.Metadata.DateRange.Begin > 0 && (s.Begin.IsZero() || b.Before(s.Begin)) {
			s.Begin = b
		}
		if e := time.Unix(fb.Metadata.DateRange.End, 0).UTC(); e.After(s.End) {
			s.End = e
		}

		for _, rec := range fb.Records {
			n := rec.Row.Count
			if n <= 0 {
				n = 1
			}
			agg := aggs[rec.Row.SourceIP]
			if agg == nil {
				agg = &srcAgg{src: &Source{IP: rec.Row.SourceIP, Verdict: VerdictOK}}
				aggs[rec.Row.SourceIP] = agg
			}
			agg.src.Messages += n
			s.Messages += n
			if rec.Row.PolicyEvaluated.SPF == "pass" {
				agg.spfPass += n
			}
			if rec.Row.PolicyEvaluated.DKIM == "pass" {
				agg.dkimPass += n
			}
			verdict, note := classify(rec)
			if verdict == VerdictOK {
				agg.src.Passed += n
				s.Passed += n
			}
			if verdict.rank() > agg.src.Verdict.rank() {
				agg.src.Verdict = verdict
				agg.src.Note = note
			}
		}
	}

	for _, agg := range aggs {
		agg.src.SPF = ratioWord(agg.spfPass, agg.src.Messages)
		agg.src.DKIM = ratioWord(agg.dkimPass, agg.src.Messages)
		s.Sources = append(s.Sources, agg.src)
	}
	sort.Slice(s.Sources, func(i, j int) bool {
		if s.Sources[i].Messages != s.Sources[j].Messages {
			return s.Sources[i].Messages > s.Sources[j].Messages
		}
		return s.Sources[i].IP < s.Sources[j].IP
	})
	s.Domains = sortedKeys(domains)
	s.Reporters = sortedKeys(reporters)
	s.Advice = buildAdvice(s)
	return s
}

func ratioWord(pass, total int) string {
	switch {
	case total == 0 || pass == 0:
		return "fail"
	case pass == total:
		return "pass"
	default:
		return "mixed"
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func buildAdvice(s *Summary) []Advice {
	var advice []Advice
	spoofMsgs, spoofSrcs, tpMsgs := 0, 0, 0
	tpNotes := map[string]bool{}
	for _, src := range s.Sources {
		switch src.Verdict {
		case VerdictSpoof:
			spoofMsgs += src.Messages
			spoofSrcs++
		case VerdictThirdParty:
			tpMsgs += src.Messages
			tpNotes[src.Note] = true
		}
	}

	if spoofMsgs > 0 {
		text := fmt.Sprintf("%d message(s) from %d source(s) had no valid authentication - likely spoofing of %s.",
			spoofMsgs, spoofSrcs, strings.Join(s.Domains, ", "))
		for _, domain := range s.Domains {
			if s.Policies[domain] == "none" {
				text += fmt.Sprintf(" %s publishes p=none, so receivers delivered these anyway; consider p=quarantine.", domain)
			}
		}
		advice = append(advice, Advice{Level: "crit", Text: text})
	}
	if tpMsgs > 0 {
		notes := sortedKeys(tpNotes)
		text := fmt.Sprintf("%d message(s) authenticate but are not aligned (%s). If these are your senders, set up a custom return-path and DKIM signing for your domain.",
			tpMsgs, strings.Join(notes, "; "))
		advice = append(advice, Advice{Level: "warn", Text: text})
	}
	if s.Messages > 0 {
		advice = append(advice, Advice{
			Level: "ok",
			Text:  fmt.Sprintf("%d of %d messages (%.0f%%) fully authenticated.", s.Passed, s.Messages, 100*float64(s.Passed)/float64(s.Messages)),
		})
	}
	return advice
}
