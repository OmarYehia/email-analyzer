# Email Header Analyzer

A CLI tool written in Go that parses raw email headers and flags phishing signals.
Built as a companion to real-world cybersecurity work involving email analysis and
phishing detection.

## What it detects

- Reply-To / From domain mismatch
- Return-Path / From domain mismatch  
- SPF / DKIM / DMARC failures
- Free mailer used with custom domain

## Usage

\`\`\`bash
./email-analyzer path/to/email.eml
\`\`\`

## Risk scoring

| Severity | Score |
|----------|-------|
| HIGH     | +30   |
| MEDIUM   | +15   |
| LOW      | +5    |

| Total Score | Risk Level  |
|-------------|-------------|
| 60+         | HIGH RISK   |
| 30–59       | MEDIUM RISK |
| 0–29        | LOW RISK    |

## Build from source

\`\`\`bash
go build -o email-analyzer .
\`\`\`

## Why I built this

I work on a cybersecurity awareness platform where phishing detection is a core
feature. This tool distills some of that thinking into a standalone utility.