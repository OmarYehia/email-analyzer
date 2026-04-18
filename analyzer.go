package main

import (
	"strings"
)

type Finding struct {
	Severity string
	Message  string
}

type AnalysisResult struct {
	Findings []Finding
	Score    int
}

func analyze(h EmailHeaders) AnalysisResult {
	result := AnalysisResult{}

	// Reply-To differs from From
	if h.ReplyTo != "" && !strings.EqualFold(extractDomain(h.From), extractDomain(h.ReplyTo)) {
		result.addFinding("HIGH", "Reply-To domain differs from From domain — common in phishing")
	}

	// Return-Path differs from From
	if h.ReturnPath != "" && !strings.EqualFold(extractDomain(h.From), extractDomain(h.ReturnPath)) {
		result.addFinding("MEDIUM", "Return-Path differs from From domain")
	}

	// SPF failures
	if h.SPFResult == "fail" || h.SPFResult == "softfail" {
		result.addFinding("HIGH", "SPF check failed - sender may be spoofed")
	} else if h.SPFResult == "none" {
		result.addFinding("MEDIUM", "No SPF record foun")
	}

	// DKIM failures
	if h.DKIMResult == "fail" {
		result.addFinding("HIGH", "DKIM signature invalid - email may be tampered")
	} else if h.DKIMResult == "none" || h.DKIMResult == "" {
		result.addFinding("MEDIUM", "No DKIM signature found")
	}

	// DMARC failures
	if h.DMARCResult == "fail" {
		result.addFinding("HIGH", "DMARC check failed")
	} else if h.DMARCResult == "none" || h.DMARCResult == "" {
		result.addFinding("MEDIUM", "No DMARC record found")
	}

	// Free mailer used with custom domains
	freeMailers := []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
	for _, fm := range freeMailers {
		if strings.Contains(strings.ToLower(h.XMailer), fm) {
			result.addFinding("LOW", "Email sent via free maile service: "+h.XMailer)
		}
	}

	return result
}

func (r *AnalysisResult) addFinding(severity, message string) {
	r.Findings = append(r.Findings, Finding{Severity: severity, Message: message})

	switch severity {
	case "HIGH":
		r.Score += 30
	case "MEDIUM":
		r.Score += 15
	case "LOW":
		r.Score += 5
	}
}

func extractDomain(email string) string {
	email = strings.Trim(email, "<>")
	parts := strings.Split(email, "@")

	if len(parts) < 2 {
		return ""
	}

	return strings.TrimSpace(parts[1])
}
