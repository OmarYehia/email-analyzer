package main

import (
	"fmt"

	"github.com/fatih/color"
)

func printResult(h EmailHeaders, r AnalysisResult) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("=== Email Header Analysis ===")
	fmt.Println()

	// Header Summary
	fmt.Printf("  From:        %s\n", h.From)
	fmt.Printf("  Reply-To:    %s\n", h.ReplyTo)
	fmt.Printf("  Subject:     %s\n", h.Subject)
	fmt.Printf("  Return-Path: %s\n", h.ReturnPath)
	fmt.Printf("  SPF:         %s\n", colorAuth(h.SPFResult))
	fmt.Printf("  DKIM:        %s\n", colorAuth(h.DKIMResult))
	fmt.Printf("  DMARC:       %s\n", colorAuth(h.DMARCResult))

	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("=== Findings ===")
	fmt.Println()

	if len(r.Findings) == 0 {
		color.Green("  No suspicious signals found.")
	} else {
		for _, f := range r.Findings {
			switch f.Severity {
			case "HIGH":
				color.Red("  [HIGH]   " + f.Message)
			case "MEDIUM":
				color.Yellow("  [MEDIUM] " + f.Message)
			case "LOW":
				color.Blue("  [LOW]    " + f.Message)
			}
		}
	}

	fmt.Println()
	printRiskLevel(r.Score)
	fmt.Println()
}

func colorAuth(result string) string {
	switch result {
	case "pass":
		return color.GreenString(result)
	case "fail", "softfail":
		return color.RedString(result)
	case "none", "":
		return color.YellowString("none")
	default:
		return result
	}
}

func printRiskLevel(score int) {
	fmt.Printf("  Risk Score: %d — ", score)
	switch {
	case score >= 60:
		color.New(color.FgRed, color.Bold).Println("HIGH RISK")
	case score >= 30:
		color.New(color.FgYellow, color.Bold).Println("MEDIUM RISK")
	default:
		color.New(color.FgGreen, color.Bold).Println("LOW RISK")
	}
}
