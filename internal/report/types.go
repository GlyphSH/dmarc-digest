// Package report parses and summarizes DMARC aggregate (RUA) reports.
package report

// Feedback is the root element of a DMARC aggregate report (RFC 7489 appendix C).
type Feedback struct {
	Metadata ReportMetadata  `xml:"report_metadata" json:"report_metadata"`
	Policy   PolicyPublished `xml:"policy_published" json:"policy_published"`
	Records  []Record        `xml:"record" json:"records"`
}

type ReportMetadata struct {
	OrgName   string `xml:"org_name" json:"org_name"`
	Email     string `xml:"email" json:"email"`
	ReportID  string `xml:"report_id" json:"report_id"`
	DateRange struct {
		Begin int64 `xml:"begin" json:"begin"`
		End   int64 `xml:"end" json:"end"`
	} `xml:"date_range" json:"date_range"`
}

type PolicyPublished struct {
	Domain          string `xml:"domain" json:"domain"`
	ADKIM           string `xml:"adkim" json:"adkim"`
	ASPF            string `xml:"aspf" json:"aspf"`
	Policy          string `xml:"p" json:"p"`
	SubdomainPolicy string `xml:"sp" json:"sp"`
	Percent         string `xml:"pct" json:"pct"`
}

type Record struct {
	Row struct {
		SourceIP        string `xml:"source_ip" json:"source_ip"`
		Count           int    `xml:"count" json:"count"`
		PolicyEvaluated struct {
			Disposition string `xml:"disposition" json:"disposition"`
			DKIM        string `xml:"dkim" json:"dkim"`
			SPF         string `xml:"spf" json:"spf"`
		} `xml:"policy_evaluated" json:"policy_evaluated"`
	} `xml:"row" json:"row"`
	Identifiers struct {
		HeaderFrom   string `xml:"header_from" json:"header_from"`
		EnvelopeFrom string `xml:"envelope_from" json:"envelope_from"`
	} `xml:"identifiers" json:"identifiers"`
	AuthResults struct {
		DKIM []AuthResult `xml:"dkim" json:"dkim"`
		SPF  []AuthResult `xml:"spf" json:"spf"`
	} `xml:"auth_results" json:"auth_results"`
}

type AuthResult struct {
	Domain   string `xml:"domain" json:"domain"`
	Selector string `xml:"selector,omitempty" json:"selector,omitempty"`
	Result   string `xml:"result" json:"result"`
}
