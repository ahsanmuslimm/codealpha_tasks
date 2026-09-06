# CodeAlpha Cybersecurity Internship — Task Portfolio

**Intern:** Muhammad Ahsan ([@ahsanmuslimm](https://github.com/ahsanmuslimm))
**Program:** CodeAlpha Cybersecurity Internship
**Repository:** [github.com/ahsanmuslimm/codealpha_tasks](https://github.com/ahsanmuslimm/codealpha_tasks)
**Period:** 2026

This repository contains the three technical tasks completed as part of the **CodeAlpha Cybersecurity Internship**. Each task is a self-contained, independently runnable project covering a different pillar of practical cybersecurity engineering: network traffic analysis, secure code review / application security, and intrusion detection & response.

Every task folder ships with its own detailed `README.md`, source code, tests, and (where applicable) sample data — this file is the top-level index that ties them together.

---

## 📁 Repository Structure

```
codealpha_tasks/
├── TASK1_BASIC-NETWORK-SNIFFER/            # Task 1 — Network packet sniffer
├── TASK2_SECURE-CODING-REVIEW/             # Task 2 — SAST/SCA secure code review platform
├── TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM/  # Task 3 — Network Intrusion Detection System
└── README.md                               # ← You are here
```

| # | Task | Folder | Core Deliverable |
|---|------|--------|-------------------|
| 1 | Basic Network Sniffer | [`TASK1_BASIC-NETWORK-SNIFFER/`](TASK1_BASIC-NETWORK-SNIFFER/) | CLI packet-capture & traffic-analysis tool |
| 2 | Secure Coding Review | [`TASK2_SECURE-CODING-REVIEW/`](TASK2_SECURE-CODING-REVIEW/) | Full-stack SAST + SCA vulnerability-scanning platform |
| 3 | Network Intrusion Detection System | [`TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM/`](TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM/) | Dual-mode NIDS with detection, response & SOC dashboard |

---

## 🧩 Task 1 — NetSentry: Basic Network Sniffer

**Goal:** Build a hands-on tool to capture and inspect live network traffic in order to understand how data flows across a network and how packet-level analysis supports threat visibility.

**What it does:**
- Captures live traffic on any interface using **Scapy**, or analyzes a saved `.pcap` file offline
- Parses and displays **TCP, UDP, ICMP, ARP, IPv4, and IPv6** traffic
- Supports **BPF-based filtering** (e.g., `tcp port 80`) and an interactive CLI mode
- Flags anomalous/suspicious traffic patterns automatically
- Exports captures/results to **CSV, JSON, and HTML reports**

**Tech stack:** Python 3.8+, Scapy, Colorama, Tabulate

**Run it:**
```bash
cd TASK1_BASIC-NETWORK-SNIFFER
pip install -r requirements.txt
python netsentry.py --interactive
```

📄 Full documentation: [`TASK1_BASIC-NETWORK-SNIFFER/README.md`](TASK1_BASIC-NETWORK-SNIFFER/README.md)

---

## 🧩 Task 2 — CodeSentry: Secure Coding Review Platform

**Goal:** Perform a structured secure-code review of multi-language applications, going beyond a single script into a repeatable, auditable review **platform**.

**What it does:**
- Ingests a codebase via **Git URL or ZIP upload**
- Runs **Semgrep (SAST)** and **OSV-Scanner (SCA)** inside isolated, resource-limited Docker workers
- Normalizes findings into a unified schema, fingerprinted and mapped to **CWE** and **OWASP Top 10 (2021)**
- Provides a **manual triage workflow** (Confirmed / False Positive / Won't Fix / Needs Review) with an immutable audit log
- Exports defensible **Markdown/PDF audit reports**
- Implements and validates **8 concrete threat mitigations** (zip-bomb DoS, path traversal, resource exhaustion, RCE, SSRF, IDOR, stored XSS, secrets leakage)
- Was run against **3 real applications** (OWASP Juice Shop, a vulnerable Flask app, a Java Spring Boot sample), producing 43 findings with a 63% confirmation rate

**Tech stack:** FastAPI, PostgreSQL, Celery + Redis, React (Vite), Docker Compose, Semgrep, OSV-Scanner

**Run it:**
```bash
cd TASK2_SECURE-CODING-REVIEW
docker-compose up --build
# Frontend → http://localhost:3000  |  API docs → http://localhost:8000/docs
```

📄 Full documentation: [`TASK2_SECURE-CODING-REVIEW/README.md`](TASK2_SECURE-CODING-REVIEW/README.md)
📄 Detailed methodology & audit results: `AUDIT_RESULTS.md`, `FINAL_PROJECT_REPORT.md` (same folder)

---

## 🧩 Task 3 — PyNIDS: Network Intrusion Detection System

**Goal:** Set up a network-based intrusion detection system capable of monitoring live traffic, detecting known attack patterns, and triggering an automated response — with or without a real Suricata deployment.

**What it does:**
- Runs **standalone** (its own packet-capture + detection engine, no Suricata required) *or* as a **Suricata EVE-log consumer**
- Ships a **34-rule Suricata/Snort-syntax signature engine** plus **6 behavioural detectors**: port scan, brute force, DoS/DDoS, ARP spoofing, DNS tunnelling, and web attacks (SQLi, XSS, traversal, Log4Shell, Shellshock, webshells)
- Includes an **automated response engine**: immediate blocking on critical alerts, escalation blocking on sustained high-severity activity, with `simulate` and `active` (real firewall) modes
- Ships a **Flask-based SOC dashboard** (zero external CDN dependencies) with live charts, alert feed, and block management
- Generates **Markdown/CSV incident reports** from the alert database
- Validated end-to-end: **75/75 smoke-test checks passed**, **30/30 pytest tests passed**, detecting all 7 phases of a scripted multi-stage attack scenario

**Tech stack:** Python 3.9+, Scapy, Flask, PyYAML, SQLite

**Run it:**
```bash
cd TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM
pip install -r requirements.txt
python run_nids.py --generate-demo-pcap
python run_nids.py --pcap demo/demo_traffic.pcap
python run_nids.py --dashboard   # → http://127.0.0.1:5000
```

📄 Full documentation: [`TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM/README.md`](TASK3_NETWORK-INTRUSION-DETECTION-SYSTEM/README.md)

---

## 🛠️ Skills Demonstrated Across This Internship

| Area | Applied In |
|---|---|
| Packet capture & protocol analysis | Task 1, Task 3 |
| Static Application Security Testing (SAST) | Task 2 |
| Software Composition Analysis (SCA) / dependency scanning | Task 2 |
| Threat modeling & mitigation validation | Task 2 |
| CWE / OWASP Top 10 / CVSS mapping | Task 2, Task 3 |
| Signature-based intrusion detection (Suricata/Snort rule syntax) | Task 3 |
| Behavioural/anomaly-based intrusion detection | Task 3 |
| Automated incident response (blocking, escalation) | Task 3 |
| Full-stack development (FastAPI, React, Flask) | Task 2, Task 3 |
| Containerization & isolation (Docker, Docker Compose) | Task 2 |
| Async task orchestration (Celery + Redis) | Task 2 |
| Automated testing (pytest, unit/integration/E2E) | Task 1, Task 2, Task 3 |
| SOC-style monitoring dashboards | Task 3 |

---

## ▶️ Getting Started

Each task is fully independent — pick the folder for the task you want to explore and follow its own `README.md` for setup. There is no shared dependency between tasks; each has its own `requirements.txt` (and, for Task 2, its own `docker-compose.yml`).

General prerequisites:
- Python 3.9+ (3.11+ recommended for Task 2's backend)
- pip / virtualenv
- Docker & Docker Compose (Task 2 only)
- Administrator/root privileges are only required for **live** packet capture (Task 1 and Task 3's `--interface` mode); offline/pcap analysis and all demos run without elevated privileges.

---

## ⚠️ Disclaimer

These tools were built for **educational and portfolio purposes** as part of a structured cybersecurity internship. They are intended for use in **isolated lab environments** and on **networks/systems you own or are explicitly authorized to test**. Live packet capture, intrusion simulation, and active firewall blocking should never be run against production or third-party systems without written authorization. Unauthorized network monitoring or intrusion testing is illegal in most jurisdictions.

## 📄 License

Each task folder carries its own license/attribution notes (see individual `README.md` files). Overall, this repository is released for educational and portfolio review as part of the CodeAlpha Cybersecurity Internship.

---

*This repository documents the complete internship deliverables for CodeAlpha's Cybersecurity track — from raw packet inspection, to secure code auditing, to full intrusion detection and response.*