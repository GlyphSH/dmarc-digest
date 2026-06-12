package report

import (
	"path/filepath"
	"testing"
)

func TestParsePlainXML(t *testing.T) {
	fb, err := ParseFile(filepath.Join("testdata", "google.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if fb.Metadata.OrgName != "google.com" {
		t.Errorf("org = %q, want google.com", fb.Metadata.OrgName)
	}
	if fb.Policy.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", fb.Policy.Domain)
	}
	if fb.Policy.Policy != "none" {
		t.Errorf("p = %q, want none", fb.Policy.Policy)
	}
	if len(fb.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(fb.Records))
	}
	if fb.Records[0].Row.Count != 412 {
		t.Errorf("first record count = %d, want 412", fb.Records[0].Row.Count)
	}
	if fb.Records[0].AuthResults.DKIM[0].Selector != "s1" {
		t.Errorf("selector = %q, want s1", fb.Records[0].AuthResults.DKIM[0].Selector)
	}
}

func TestParseGzip(t *testing.T) {
	fb, err := ParseFile(filepath.Join("testdata", "sendgrid.xml.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if fb.Metadata.OrgName != "Yahoo" {
		t.Errorf("org = %q, want Yahoo", fb.Metadata.OrgName)
	}
	if len(fb.Records) != 1 || fb.Records[0].Row.SourceIP != "167.89.12.7" {
		t.Errorf("unexpected records: %+v", fb.Records)
	}
}

func TestParseZip(t *testing.T) {
	fb, err := ParseFile(filepath.Join("testdata", "outlook.zip"))
	if err != nil {
		t.Fatal(err)
	}
	if fb.Metadata.OrgName != "Outlook.com" {
		t.Errorf("org = %q, want Outlook.com", fb.Metadata.OrgName)
	}
	if len(fb.Records) != 1 || fb.Records[0].Row.Count != 13 {
		t.Errorf("unexpected records: %+v", fb.Records)
	}
}

func TestParseMissingFile(t *testing.T) {
	if _, err := ParseFile(filepath.Join("testdata", "nope.xml")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseNotAReport(t *testing.T) {
	if _, err := ParseFile(filepath.Join("testdata", "notareport.xml")); err == nil {
		t.Error("expected error for non-DMARC xml")
	}
}
