package report

import (
	"archive/zip"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseFile reads a DMARC aggregate report from a plain .xml file, a .xml.gz
// file, or a .zip archive containing an .xml entry — the three forms reporting
// orgs actually send.
func ParseFile(path string) (*Feedback, error) {
	switch {
	case strings.HasSuffix(path, ".zip"):
		return parseZip(path)
	case strings.HasSuffix(path, ".gz"):
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		return parse(path, gz)
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return parse(path, f)
	}
}

func parseZip(path string) (*Feedback, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer zr.Close()
	for _, entry := range zr.File {
		if !strings.HasSuffix(entry.Name, ".xml") {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer rc.Close()
		return parse(path, rc)
	}
	return nil, fmt.Errorf("%s: no .xml entry in archive", path)
}

func parse(path string, r io.Reader) (*Feedback, error) {
	var fb Feedback
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&fb); err != nil {
		return nil, fmt.Errorf("%s: invalid DMARC report: %w", path, err)
	}
	if fb.Policy.Domain == "" && len(fb.Records) == 0 {
		return nil, fmt.Errorf("%s: not a DMARC aggregate report", path)
	}
	return &fb, nil
}
