package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, name string) *Feedback {
	t.Helper()
	fb, err := ParseFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return fb
}

func testSummary(t *testing.T) *Summary {
	t.Helper()
	return Summarize([]*Feedback{
		mustParse(t, "google.xml"),
		mustParse(t, "sendgrid.xml"),
		mustParse(t, "outlook.xml"),
	})
}

func TestSummarizeTotals(t *testing.T) {
	s := testSummary(t)
	if s.Reports != 3 {
		t.Errorf("reports = %d, want 3", s.Reports)
	}
	if s.Messages != 514 {
		t.Errorf("messages = %d, want 514", s.Messages)
	}
	if s.Passed != 425 {
		t.Errorf("passed = %d, want 425", s.Passed)
	}
	if len(s.Sources) != 4 {
		t.Fatalf("sources = %d, want 4", len(s.Sources))
	}
	// Sorted by message count descending.
	if s.Sources[0].IP != "209.85.220.41" || s.Sources[0].Messages != 412 {
		t.Errorf("top source = %+v, want 209.85.220.41/412", s.Sources[0])
	}
}

func TestSummarizeMetadata(t *testing.T) {
	s := testSummary(t)
	if len(s.Domains) != 1 || s.Domains[0] != "example.com" {
		t.Errorf("domains = %v", s.Domains)
	}
	wantReporters := []string{"Outlook.com", "Yahoo", "google.com"}
	if strings.Join(s.Reporters, ",") != strings.Join(wantReporters, ",") {
		t.Errorf("reporters = %v, want %v", s.Reporters, wantReporters)
	}
	if s.Policies["example.com"] != "none" {
		t.Errorf("policy = %q, want none", s.Policies["example.com"])
	}
	if got := s.Begin.UTC().Format(time.DateOnly); got != "2026-05-01" {
		t.Errorf("begin = %s, want 2026-05-01", got)
	}
	if got := s.End.UTC().Format(time.DateOnly); got != "2026-05-03" {
		t.Errorf("end = %s, want 2026-05-03", got)
	}
}

func TestVerdicts(t *testing.T) {
	s := testSummary(t)
	byIP := map[string]*Source{}
	for _, src := range s.Sources {
		byIP[src.IP] = src
	}
	if v := byIP["209.85.220.41"].Verdict; v != VerdictOK {
		t.Errorf("google source verdict = %s, want ok", v)
	}
	if v := byIP["185.243.57.99"].Verdict; v != VerdictSpoof {
		t.Errorf("spoof source verdict = %s, want suspected-spoofing", v)
	}
	tp := byIP["167.89.12.7"]
	if tp.Verdict != VerdictThirdParty {
		t.Errorf("sendgrid source verdict = %s, want third-party", tp.Verdict)
	}
	if !strings.Contains(tp.Note, "sendgrid.net") {
		t.Errorf("third-party note = %q, want mention of sendgrid.net", tp.Note)
	}
}

func TestExitCodes(t *testing.T) {
	all := testSummary(t)
	if got := all.ExitCode(); got != 2 {
		t.Errorf("exit with spoofing = %d, want 2", got)
	}
	tpOnly := Summarize([]*Feedback{mustParse(t, "sendgrid.xml")})
	if got := tpOnly.ExitCode(); got != 1 {
		t.Errorf("exit with third-party only = %d, want 1", got)
	}
	clean := Summarize([]*Feedback{mustParse(t, "outlook.xml")})
	if got := clean.ExitCode(); got != 0 {
		t.Errorf("exit when clean = %d, want 0", got)
	}
}

func TestAdvice(t *testing.T) {
	s := testSummary(t)
	var crit, warn, ok string
	for _, a := range s.Advice {
		switch a.Level {
		case "crit":
			crit = a.Text
		case "warn":
			warn = a.Text
		case "ok":
			ok = a.Text
		}
	}
	if !strings.Contains(crit, "spoofing") || !strings.Contains(crit, "p=quarantine") {
		t.Errorf("crit advice = %q, want spoofing + p=quarantine suggestion", crit)
	}
	if !strings.Contains(warn, "sendgrid.net") {
		t.Errorf("warn advice = %q, want sendgrid.net mention", warn)
	}
	if !strings.Contains(ok, "83%") {
		t.Errorf("ok advice = %q, want 83%% authenticated", ok)
	}
}

func TestMixedAlignment(t *testing.T) {
	fb := mustParse(t, "google.xml")
	// Force both records onto one IP: 412 aligned + 37 unaligned = mixed.
	fb.Records[1].Row.SourceIP = fb.Records[0].Row.SourceIP
	s := Summarize([]*Feedback{fb})
	if len(s.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(s.Sources))
	}
	src := s.Sources[0]
	if src.SPF != "mixed" || src.DKIM != "mixed" {
		t.Errorf("spf/dkim = %s/%s, want mixed/mixed", src.SPF, src.DKIM)
	}
	if src.Verdict != VerdictSpoof {
		t.Errorf("verdict = %s, want worst verdict (suspected-spoofing)", src.Verdict)
	}
}

func TestZeroCountTreatedAsOne(t *testing.T) {
	fb := mustParse(t, "outlook.xml")
	fb.Records[0].Row.Count = 0
	s := Summarize([]*Feedback{fb})
	if s.Messages != 1 {
		t.Errorf("messages = %d, want 1 (zero count defaults to 1)", s.Messages)
	}
}
