package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func testdata(name string) string {
	return filepath.Join("internal", "report", "testdata", name)
}

func TestRunHuman(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-no-dns", testdata("google.xml"), testdata("sendgrid.xml.gz"), testdata("outlook.zip")}, &out, &errOut)
	if code != 2 {
		t.Errorf("exit = %d, want 2 (spoofing present); stderr: %s", code, errOut.String())
	}
	text := out.String()
	for _, want := range []string{"514 messages", "185.243.57.99", "suspected-spoofing", "WHAT TO DO", "p=quarantine"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
}

func TestRunJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-no-dns", "-json", testdata("google.xml")}, &out, &errOut)
	if code != 2 {
		t.Errorf("exit = %d, want 2; stderr: %s", code, errOut.String())
	}
	var got struct {
		Messages int `json:"messages"`
		Sources  []struct {
			IP      string `json:"ip"`
			Verdict string `json:"verdict"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if got.Messages != 449 {
		t.Errorf("messages = %d, want 449", got.Messages)
	}
	if len(got.Sources) != 2 {
		t.Errorf("sources = %d, want 2", len(got.Sources))
	}
}

func TestRunDirectory(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-no-dns", filepath.Join("internal", "report", "testdata")}, &out, &errOut)
	// notareport.xml in the directory must make the run fail cleanly.
	if code != 2 || !strings.Contains(errOut.String(), "notareport.xml") {
		t.Errorf("exit = %d, stderr = %q; want parse failure mentioning notareport.xml", code, errOut.String())
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("stderr missing usage: %s", errOut.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "dmarc-digest") {
		t.Errorf("version output = %q", out.String())
	}
}
