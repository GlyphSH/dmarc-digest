// dmarc-digest turns DMARC aggregate (RUA) XML reports into a readable
// summary: who is sending as your domain, who is spoofing it, and what to fix.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/GlyphSH/dmarc-digest/internal/report"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dmarc-digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit the summary as JSON")
	noDNS := fs.Bool("no-dns", false, "skip reverse-DNS lookups of source IPs")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: dmarc-digest [flags] <report.xml | report.xml.gz | report.zip | dir> ...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "dmarc-digest", version)
		return 0
	}
	paths, err := expandPaths(fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "dmarc-digest: %v\n", err)
		return 2
	}
	if len(paths) == 0 {
		fs.Usage()
		return 2
	}

	var feedbacks []*report.Feedback
	for _, p := range paths {
		fb, err := report.ParseFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "dmarc-digest: %v\n", err)
			return 2
		}
		feedbacks = append(feedbacks, fb)
	}
	summary := report.Summarize(feedbacks)
	if !*noDNS {
		resolvePTRs(summary)
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			fmt.Fprintf(stderr, "dmarc-digest: %v\n", err)
			return 2
		}
	} else {
		writeHuman(stdout, summary)
	}
	return summary.ExitCode()
}

// expandPaths accepts files and directories; a directory contributes every
// report-shaped file directly inside it.
func expandPaths(args []string) ([]string, error) {
	var paths []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}
		entries, err := os.ReadDir(arg)
		if err != nil {
			return nil, err
		}
		found := false
		for _, e := range entries {
			name := e.Name()
			if strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".xml.gz") || strings.HasSuffix(name, ".zip") {
				paths = append(paths, filepath.Join(arg, name))
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%s: no .xml, .xml.gz, or .zip reports in directory", arg)
		}
	}
	return paths, nil
}

func resolvePTRs(s *report.Summary) {
	for _, src := range s.Sources {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := net.DefaultResolver.LookupAddr(ctx, src.IP)
		cancel()
		if err == nil && len(names) > 0 {
			src.PTR = strings.TrimSuffix(names[0], ".")
		}
	}
}

func writeHuman(w io.Writer, s *report.Summary) {
	fmt.Fprintf(w, "%d report(s) · %s · %s → %s · %d messages\n\n",
		s.Reports, strings.Join(s.Domains, ", "),
		s.Begin.Format("2006-01-02"), s.End.Format("2006-01-02"), s.Messages)

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tPTR\tMSGS\tSPF\tDKIM\tDMARC\tVERDICT")
	for _, src := range s.Sources {
		ptr := src.PTR
		if ptr == "" {
			ptr = "-"
		}
		verdict := string(src.Verdict)
		if src.Note != "" {
			verdict += ": " + src.Note
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			src.IP, ptr, src.Messages, src.SPF, src.DKIM, dmarcWord(src), verdict)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nWHAT TO DO")
	icons := map[string]string{"crit": "✗", "warn": "⚠", "ok": "✓"}
	for _, a := range s.Advice {
		fmt.Fprintf(w, " %s %s\n", icons[a.Level], a.Text)
	}
}

func dmarcWord(src *report.Source) string {
	switch {
	case src.Passed == src.Messages:
		return "pass"
	case src.Passed == 0:
		return "FAIL"
	default:
		return "mixed"
	}
}
