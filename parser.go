package main

import (
	"bufio"
	"strings"
)

func parseHeaders(raw string) EmailHeaders {
	headers := EmailHeaders{}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(lines) > 0 {
			lines[len(lines)-1] = lines[len(lines)-1] + " " + strings.TrimSpace(line)
		} else {
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "From:") {
			headers.From = extractValue(line)
		} else if strings.HasPrefix(line, "Reply-To:") {
			headers.ReplyTo = extractValue(line)
		} else if strings.HasPrefix(line, "Subject:") {
			headers.Subject = extractValue(line)
		} else if strings.HasPrefix(line, "Return-Path:") {
			headers.ReturnPath = extractValue(line)
		} else if strings.HasPrefix(line, "X-Mailer:") {
			headers.XMailer = extractValue(line)
		} else if strings.HasPrefix(line, "Received:") {
			headers.ReceivedIPs = append(headers.ReceivedIPs, line)
		} else if strings.HasPrefix(line, "Authentication-Results:") {
			headers.SPFResult = extractAuthResult(line, "spf=")
			headers.DKIMResult = extractAuthResult(line, "dkim=")
			headers.DMARCResult = extractAuthResult(line, "dmarc=")
		}
	}

	return headers
}

func extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func extractAuthResult(line string, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx == -1 {
		return ""
	}
	rest := line[idx+len(prefix):]
	fields := strings.Fields(rest)

	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
