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

```bash
./email-analyzer path/to/email.eml
```

## Examples

Three example emails are included in the `examples/` folder:

**Low risk — legitimate GitHub email**
```bash
./email-analyzer examples/legit.eml
# Risk Score: 0 — LOW RISK
```

**Medium risk — missing DKIM/DMARC, suspicious Return-Path**
```bash
./email-analyzer examples/medium.eml
# Risk Score: 45 — MEDIUM RISK
```

**High risk — phishing simulation**
```bash
./email-analyzer examples/high.eml
# Risk Score: 135 — HIGH RISK
```

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

Requires Go 1.21+

```bash
git clone https://github.com/yourusername/email-analyzer
cd email-analyzer
go build -o email-analyzer .
./email-analyzer examples/high.eml
```

## Why I built this

I work on a cybersecurity awareness platform where phishing detection is a core
feature. This tool distills some of that thinking into a standalone utility —
parsing the same signals (SPF, DKIM, DMARC, domain mismatches) that real email
security systems rely on.