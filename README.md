# CyberTrace

### Digital Forensics Investigation Platform

[![Live Demo](https://img.shields.io/badge/Live-Demo-111111?style=for-the-badge)](https://cybertrace-forensics.up.railway.app)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-111111?style=for-the-badge&logo=github)](https://github.com/gnapiika/CyberTrace)

---

## Overview

CyberTrace is a web-based digital forensics investigation platform that analyzes collected digital evidence, reconstructs chronological activity, detects suspicious behavior, correlates events across multiple evidence sources, calculates a heuristic risk score, and generates investigation reports.

The platform is designed to help investigators understand:

- What happened
- When it happened
- Which evidence sources were involved
- Which activities may be suspicious
- How individual events are related
- What the overall investigation risk level is

CyberTrace follows a forensic workflow where evidence is analyzed without executing files found inside the evidence.

---

## Live Demo

**Application:**  
https://cybertrace-forensics.up.railway.app

**GitHub Repository:**  
https://github.com/gnapiika/CyberTrace

---

## Key Features

- Case management
- Evidence upload
- SHA-256 evidence integrity verification
- ZIP evidence extraction
- Evidence source identification
- Browser history analysis
- Authentication log analysis
- File activity analysis
- USB activity analysis
- Network activity analysis
- Process activity analysis
- Event normalization
- Chronological investigation timeline
- Suspicious activity detection
- Cross-source event correlation
- Heuristic risk scoring
- Investigation dashboard
- PDF investigation report generation
- Case deletion and evidence cleanup

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
