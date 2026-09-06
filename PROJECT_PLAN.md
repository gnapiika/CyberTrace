# CyberTrace

## Problem Statement

Digital forensic investigations often require investigators to manually
examine large amounts of logs and system artifacts from different sources.

This process can be time-consuming and makes it difficult to understand
the chronological sequence of suspicious activities.

CyberTrace is a digital forensics investigation platform designed to
automatically collect, parse, normalize, correlate, and visualize
forensic events from multiple evidence sources.

The system reconstructs suspicious activity chronologically and provides
investigators with a unified timeline and investigation report.

## Objective

The primary objective of CyberTrace is to develop a centralized digital
forensics platform that can analyze different types of forensic evidence
and reconstruct suspicious activity as a chronological timeline.

The system will help investigators:

1. Upload forensic evidence.
2. Extract relevant artifacts.
3. Analyze different evidence sources.
4. Normalize events into a common format.
5. Detect suspicious activity.
6. Correlate related events.
7. Reconstruct an incident timeline.
8. Generate an investigation report.

## Evidence Sources

CyberTrace will analyze multiple types of digital forensic artifacts. Each
source will be processed by a dedicated parser and converted into a
standardized event format.

### 1. Browser Activity

The browser parser will analyze browser history and identify:

* Visited URLs
* Website titles
* Download activity
* Access timestamps
* Suspicious or unusual URLs

Example:

09:10 → google.com visited
09:15 → suspicious-site.com visited
09:17 → suspicious.exe downloaded

---

### 2. Authentication Logs

The authentication parser will analyze login-related events:

* Username
* Source IP address
* Login timestamp
* Successful login attempts
* Failed login attempts
* Repeated login attempts

Example:

02:30 → admin → FAILED
02:31 → admin → FAILED
02:32 → admin → FAILED
02:33 → admin → SUCCESS

These events can later be correlated to identify possible brute-force
or account-compromise activity.

---

### 3. File Activity

The file activity parser will analyze:

* File creation
* File modification
* File deletion
* File copying
* File execution
* File path
* User associated with the activity
* Timestamp

Example:

10:30 → suspicious.exe CREATED
10:31 → suspicious.exe EXECUTED
10:32 → suspicious.exe DELETED

---

### 4. USB Device Activity

The USB parser will analyze removable-device activity:

* Device connection
* Device disconnection
* Device identifier
* Device name
* File-copy events
* User
* Timestamp

Example:

11:00 → USB DEVICE CONNECTED
11:04 → confidential.pdf COPIED
11:10 → USB DEVICE DISCONNECTED

---

### 5. Network Activity

The network parser will analyze network-related events:

* Source IP address
* Destination IP address
* Port
* Protocol
* Timestamp
* Connection status

Example:

12:00 → 192.168.1.20 → 185.10.20.30 → Port 443

These events can later be correlated with other activity such as
suspicious processes or downloads.

---

### 6. Process Activity

The process parser will analyze running-process information:

* Process name
* Process ID (PID)
* Parent process ID
* Username
* Executable path
* Start timestamp

Example:

12:10 → winword.exe started
12:11 → powershell.exe started
12:12 → suspicious.exe started

Process relationships can later be analyzed to identify potentially
suspicious process chains.

---

## Evidence Input Format

For the initial version, CyberTrace will accept a ZIP-based evidence
package containing structured forensic artifacts.

Supported file formats:

* CSV
* LOG
* JSON
* TXT

Example evidence package:

case_001.zip

├── browser/
│   └── history.csv
│
├── authentication/
│   └── auth.log
│
├── files/
│   └── file_activity.csv
│
├── usb/
│   └── usb_events.csv
│
├── network/
│   └── network.log
│
└── processes/
└── processes.csv

## Initial Limitations

The initial version of CyberTrace will focus on forensic evidence analysis
and incident timeline reconstruction. It will not attempt to replace
professional digital forensic investigation tools.

CyberTrace will initially NOT:

1. Perform live monitoring of computers or networks.

2. Execute files found inside forensic evidence.

3. Modify or delete the original forensic evidence.

4. Automatically determine that a cyberattack definitely occurred.

5. Perform unrestricted malware execution or dynamic malware analysis.

6. Perform full disk-image analysis such as raw disk imaging in the initial
   version.

7. Automatically attribute an incident to a specific person or attacker.

8. Take automated defensive actions such as deleting files, blocking IP
   addresses, or disabling user accounts.

9. Modify the system from which forensic evidence was collected.

10. Treat a suspicious event as proof of malicious activity.

CyberTrace will instead provide evidence-based findings, suspicious-activity
alerts, event correlation, and chronological timelines to assist an
investigator.

All suspicious-activity detections will be presented as potential or
possible indicators rather than definitive conclusions.

## Output

After analyzing the uploaded evidence, CyberTrace will present the
investigator with a centralized investigation dashboard.

The system will provide the following outputs.

### 1. Investigation Dashboard

The dashboard will provide an overview of the case, including:

* Case ID
* Case name
* Evidence information
* Total number of events
* Number of suspicious events
* Number of alerts
* Overall risk score
* Evidence integrity status

Example:

Case: CT-001

Total Events: 1,284
Suspicious Events: 17
High-Severity Alerts: 5
Risk Score: 82/100
Evidence Integrity: VERIFIED

---

### 2. Event Timeline

CyberTrace will reconstruct events chronologically using their timestamps.

Example:

09:12 → Browser activity detected
09:14 → Suspicious file downloaded
09:16 → Process started
09:17 → External network connection detected
09:20 → USB device connected
09:22 → Sensitive file copied
09:25 → USB device disconnected

The timeline will allow investigators to understand the sequence of
activities during an incident.

---

### 3. Suspicious Activity Alerts

CyberTrace will identify potentially suspicious patterns and display
alerts with a severity level.

Example:

HIGH — Possible brute-force activity

HIGH — Possible data transfer through USB

MEDIUM — Suspicious process execution

LOW — Unusual browser activity

Each alert will contain an explanation describing the events or pattern
that caused it.

---

### 4. Event Details

Investigators will be able to inspect individual events.

An event may contain:

* Timestamp
* Event type
* Evidence source
* Username
* IP address
* File path
* Process name
* Description
* Severity
* Original event information

---

### 5. Risk Score

CyberTrace will calculate a heuristic risk score based on suspicious
events and their severity.

The score will range from 0 to 100.

Risk levels:

0–20   → LOW
21–40  → MODERATE
41–60  → MEDIUM
61–80  → HIGH
81–100 → CRITICAL

The risk score will be used to prioritize investigation and will not
represent definitive proof that an attack occurred.

---

### 6. Investigation Summary

CyberTrace will provide a concise summary of the major events identified
during the investigation.

For example:

"Multiple failed authentication attempts were followed by a successful
login. Shortly afterward, a suspicious executable was downloaded and
executed. An external network connection was then observed."

The summary will be based on the evidence and detected event patterns.

---

### 7. Investigation Report

CyberTrace will allow the investigator to generate a report containing:

* Case information
* Evidence information
* Evidence hash
* Analysis date
* Evidence sources
* Extracted events
* Suspicious activity
* Risk score
* Chronological timeline
* Investigation summary
* Conclusion

The report will be available as a PDF for documentation and review.

## MVP Features

The Minimum Viable Product (MVP) of CyberTrace will focus on the core
features required to perform digital forensic evidence analysis and
timeline reconstruction.

### 1. Case Management

Investigators will be able to:

* Create a new investigation case.
* Assign a unique case ID.
* Add a case name and description.
* View the status of an investigation.

### 2. Evidence Upload

Investigators will be able to upload forensic evidence packages.

The initial version will support:

* ZIP files
* CSV files
* LOG files
* JSON files
* TXT files

### 3. Evidence Integrity Verification

CyberTrace will calculate a SHA-256 hash for uploaded evidence.

The hash will be stored with the case information so that the integrity
of the evidence can be verified during the investigation.

### 4. Evidence Parsing

CyberTrace will use dedicated parsers to extract events from:

* Browser history
* Authentication logs
* File activity
* USB activity
* Network activity
* Process activity

### 5. Event Normalization

Events from different evidence sources will be converted into a common
event structure containing fields such as:

* Timestamp
* Event type
* Source
* User
* IP address
* File path
* Process name
* Description
* Severity

### 6. Event Storage

Normalized events will be stored in an SQLite database and associated
with the corresponding investigation case.

### 7. Timeline Reconstruction

CyberTrace will sort events chronologically and generate an investigation
timeline.

The timeline will allow investigators to understand how activities
occurred over time.

### 8. Suspicious Activity Detection

CyberTrace will use rule-based detection to identify potentially
suspicious patterns.

Initial detection rules will include:

* Repeated failed login attempts
* Suspicious downloads followed by execution
* Suspicious process chains
* USB connection followed by sensitive file copying
* Unusual network connections

### 9. Event Correlation

Related events from different evidence sources will be correlated to
identify larger activity patterns.

For example:

Browser Download
→ File Creation
→ Process Execution
→ Network Connection

may be correlated as a potential suspicious execution chain.

### 10. Risk Scoring

CyberTrace will assign a heuristic risk score from 0 to 100 based on
detected suspicious activity.

### 11. Investigation Dashboard

The dashboard will display:

* Case information
* Event statistics
* Suspicious events
* Alerts
* Risk score
* Evidence integrity status
* Investigation timeline

### 12. Investigation Report

Investigators will be able to generate a report containing the major
findings, evidence information, detected alerts, timeline, and
investigation summary.

## System Architecture

CyberTrace will follow a modular architecture in which evidence is
uploaded, processed by specialized parsers, converted into standardized
events, analyzed for suspicious activity, and presented through an
investigation interface.

### High-Level Architecture

Investigator
|
v
Web Interface
|
v
Case & Evidence Manager
|
v
Evidence Extraction
|
+-------------------+
|                   |
v                   v
Evidence Integrity    File Identification
(Hashing)                  |
v
+----------+----------+
|          |          |
v          v          v
Browser     Auth       File
Parser      Parser     Parser
|          |          |
+----------+----------+
|
+----------+----------+
|          |          |
v          v          v
USB       Network     Process
Parser      Parser      Parser
|          |          |
+----------+----------+
|
v
Event Normalization
|
v
SQLite Database
|
v
Correlation Engine
|
v
Detection Engine
|
+------+------+
|             |
v             v
Risk Scoring   Timeline Engine
|             |
+------+------+
|
v
Investigation Dashboard
|
+------+------+
|             |
v             v
Alerts & Events  PDF Report

### Main Components

#### 1. Web Interface

Provides the interface through which investigators create cases, upload
evidence, view events, inspect alerts, and generate reports.

#### 2. Case and Evidence Manager

Manages investigation cases and uploaded evidence.

#### 3. Evidence Integrity Module

Calculates and stores SHA-256 hashes of evidence files.

#### 4. Evidence Parsers

Specialized modules extract useful information from different evidence
sources.

#### 5. Event Normalization Module

Converts events from different sources into a standardized structure.

#### 6. SQLite Database

Stores cases, evidence metadata, normalized events, alerts, and analysis
results.

#### 7. Correlation Engine

Connects related events from different evidence sources.

#### 8. Detection Engine

Applies predefined rules to identify potentially suspicious activity.

#### 9. Risk Scoring Engine

Calculates a heuristic risk score based on detected activity.

#### 10. Timeline Engine

Sorts and groups events chronologically to reconstruct the sequence of
activities.

#### 11. Reporting Module

Generates a structured investigation report.

#### 12. Dashboard

Presents investigation findings through tables, statistics, alerts,
and a visual timeline.


## Detection Rules

CyberTrace will initially use a rule-based detection engine to identify
potentially suspicious activity.

The rules will analyze individual events as well as combinations of
related events.

### Rule 1 — Possible Brute-Force Activity

Condition:

* Five or more failed login attempts occur within a short time period.
* A successful login occurs after the failed attempts.

Example:

FAILED → FAILED → FAILED → FAILED → FAILED → SUCCESS

Alert:

Possible brute-force activity.

Severity:

HIGH

---

### Rule 2 — Suspicious File Execution

Condition:

* A potentially suspicious executable is downloaded.
* The downloaded file is subsequently executed.

Example:

Browser Download
→ File Created
→ File Executed

Alert:

Possible suspicious file execution.

Severity:

HIGH

---

### Rule 3 — Suspicious Process Chain

Condition:

A potentially unusual parent-child process relationship is detected.

Example:

Document Application
→ PowerShell
→ Suspicious Process

Alert:

Potentially suspicious process chain.

Severity:

HIGH

---

### Rule 4 — Possible USB Data Transfer

Condition:

* A USB device is connected.
* A sensitive or important file is accessed or copied.
* The USB device is subsequently disconnected.

Example:

USB Connected
→ Sensitive File Copied
→ USB Disconnected

Alert:

Possible data transfer through removable media.

Severity:

HIGH

---

### Rule 5 — Suspicious Network Activity

Condition:

A suspicious or unusual network connection occurs near another
potentially suspicious event.

Example:

Suspicious Process
→ External Network Connection

Alert:

Potentially suspicious network activity.

Severity:

MEDIUM

---

### Rule 6 — File Created and Immediately Deleted

Condition:

A file is created, executed or accessed, and deleted shortly afterward.

Example:

File Created
→ File Executed
→ File Deleted

Alert:

Suspicious file lifecycle detected.

Severity:

MEDIUM

---

### Rule 7 — Multiple Suspicious Events

Condition:

Multiple suspicious events occur within a defined time window.

Example:

Suspicious Download
→ Process Execution
→ Network Connection
→ USB Activity

Alert:

Multiple correlated suspicious events detected.

Severity:

CRITICAL

---

## Detection Philosophy

Detection rules will identify indicators and patterns that may require
further investigation.

An alert will not automatically establish that malicious activity
occurred.

Every alert will include:

* Detection rule
* Triggering events
* Timestamp
* Severity
* Explanation
* Related events

## Investigation Workflow

CyberTrace will follow a structured workflow from evidence acquisition
through investigation reporting.

### Step 1 — Create Case

The investigator creates a new case and provides:

* Case name
* Description
* Investigator information

CyberTrace generates a unique case ID.

---

### Step 2 — Upload Evidence

The investigator uploads the forensic evidence package.

CyberTrace records the evidence filename and metadata.

---

### Step 3 — Verify Evidence Integrity

CyberTrace calculates a SHA-256 hash of the uploaded evidence.

The hash is stored with the case to support later integrity verification.

---

### Step 4 — Extract Evidence

If the evidence is provided as a ZIP package, CyberTrace extracts the
contents into a controlled analysis directory.

The original evidence package remains unchanged.

---

### Step 5 — Identify Evidence Sources

CyberTrace examines the extracted files and identifies their source
based on their location, format, and structure.

Examples:

browser/history.csv → Browser Parser

authentication/auth.log → Authentication Parser

files/file_activity.csv → File Parser

usb/usb_events.csv → USB Parser

---

### Step 6 — Parse Evidence

The appropriate parser extracts useful information from each artifact.

---

### Step 7 — Normalize Events

Events from different sources are converted into the common CyberTrace
event structure.

Each event receives information such as:

* Timestamp
* Event type
* Source
* User
* Description
* Relevant technical details

---

### Step 8 — Store Events

Normalized events are stored in the SQLite database and associated with
the relevant case.

---

### Step 9 — Detect Suspicious Activity

The detection engine applies predefined rules to the extracted events.

Potentially suspicious events generate alerts.

---

### Step 10 — Correlate Events

CyberTrace examines related events from different sources.

For example:

Browser Download
→ File Creation
→ Process Execution
→ Network Connection

can be grouped into a single suspicious activity chain.

---

### Step 11 — Calculate Risk Score

The risk scoring engine calculates an overall heuristic risk score
based on the detected activity.

---

### Step 12 — Generate Timeline

All relevant events are ordered chronologically.

The investigator can filter the timeline by:

* Date
* Time
* Event type
* Evidence source
* User
* IP address
* Severity

---

### Step 13 — Investigate Alerts

The investigator can select an alert and inspect the events that caused
it.

Each alert will provide an explanation and links to related events.

---

### Step 14 — Generate Investigation Summary

CyberTrace creates a structured summary describing the important events
and detected patterns.

---

### Step 15 — Generate Final Report

The investigator can generate a PDF report containing:

* Case information
* Evidence information
* Evidence hash
* Analysis information
* Detected alerts
* Event timeline
* Risk score
* Investigation summary
* Conclusion


