# CyberTrace

### Digital Forensics Investigation Platform & Incident Analysis Platform

CyberTrace is a digital forensics investigation platform that analyzes forensic evidence, reconstructs chronological activity, correlates events across multiple evidence sources, and identifies potentially suspicious behavior using deterministic detection rules.

**Live Demo:** https://cybertrace-forensics.up.railway.app

---

## Overview

Digital investigations often involve evidence collected from multiple sources such as authentication logs, browser activity, file activity, USB devices, network connections, and process execution.

CyberTrace brings these sources together into a single investigation workflow.

The platform transforms raw forensic evidence into:

- Normalized forensic events
- Chronological investigation timelines
- Suspicious activity alerts
- Cross-source event correlations
- Heuristic risk scores
- Investigation summaries
- PDF investigation reports

The goal is to help investigators move from raw evidence to a coherent reconstruction of what happened.

---

## Investigation Workflow

```text
Forensic Evidence
       ↓
SHA-256 Integrity Verification
       ↓
Evidence Extraction
       ↓
Evidence Source Identification
       ↓
Specialized Parsers
       ↓
Event Normalization
       ↓
SQLite / PostgreSQL Storage
       ↓
Detection Engine
       ↓
Correlation Engine
       ↓
Risk Scoring
       ↓
Chronological Timeline
       ↓
Investigation Dashboard
       ↓
PDF Investigation Report
## Screenshots

### CyberTrace Homepage

![CyberTrace Homepage](screenshots/homepage.png)

### Investigation Dashboard

![Investigation Dashboard](screenshots/dashboard.png)

### Case Details

![Case Details](screenshots/case-details.png)

### Suspicious Activity Alerts

![Alerts](screenshots/alerts.png)

### Event Correlation

![Correlation](screenshots/correlation.png)

### Investigation Timeline

![Timeline](screenshots/timeline.png)
Add CyberTrace screenshots to README
