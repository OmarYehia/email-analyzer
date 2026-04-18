package main

import (
	"fmt"
	"os"
)

type EmailHeaders struct {
	From        string
	ReplyTo     string
	Subject     string
	ReturnPath  string
	ReceivedIPs []string
	SPFResult   string
	DKIMResult  string
	DMARCResult string
	XMailer     string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: email-analyzer <file.eml>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	headers := parseHeaders(string(data))
	result := analyze(headers)

	printResult(headers, result)
}
