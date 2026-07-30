# DevSecOps-Agent-V1
A modular DevSecOps security pipeline designed for automated code and dependency security analysis with support for multi-tool orchestration, finding normalization, risk assessment, compliance mapping, and future AI-powered vulnerability management.

# AI DevSecOps Security Pipeline

<p align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/DevSecOps-Automated-red)

</p>

A modular **Python-based DevSecOps Security Pipeline** that automates security analysis by orchestrating multiple open-source security tools, correlating findings, removing duplicates, calculating risk scores, mapping compliance controls, and generating professional security reports.

> **Repository Scope**
>
> This repository contains the **core DevSecOps Pipeline**.
>
> AI-powered vulnerability reasoning, intelligent remediation, patch prioritization, and LLM integration are under active development and are intentionally excluded from this repository.

---

# Table of Contents

* Features
* Installation
* Supported Security Tools
* Project Architecture
* Project Structure
* Configuration
* Running the Pipeline
* Finding Processing
* Generated Reports
* Example Output
* Roadmap
* Contributing
* License

---

# Features

* Modular architecture
* Multi-tool orchestration
* Static Application Security Testing (SAST)
* Dependency vulnerability scanning (SCA)
* Container security scanning
* Secret detection
* SBOM generation
* Finding normalization
* Duplicate removal
* Vulnerability correlation
* Risk score calculation
* Compliance mapping
* Multi-format reporting
* Easy integration into CI/CD pipelines
* Extensible executor framework

---

# Installation

## Clone Repository

```bash
git clone https://github.com/<YOUR_USERNAME>/AI-DevSecOps-Security-Pipeline.git

cd AI-DevSecOps-Security-Pipeline
```

---

## Create Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Install Required Security Tools

The following tools must be installed and available in your system PATH.

| Tool        | Purpose                             |
| ----------- | ----------------------------------- |
| Semgrep     | Static Application Security Testing |
| OSV Scanner | Dependency Vulnerability Scanning   |
| Syft        | SBOM Generation                     |
| Grype       | SBOM Vulnerability Matching         |
| Trivy       | Container Security                  |
| Gitleaks    | Secret Detection                    |

---

# Project Architecture

```
                     Target Repository
                             │
                             ▼
                     Security Orchestrator
                             │
                 Execution Planner
                             │
                 Executor Manager
                             │
     ┌────────────┬────────────┬────────────┬────────────┐
     ▼            ▼            ▼            ▼
 Semgrep      Dependency      Trivy      Gitleaks
               Security
        (OSV + Syft + Grype)
     │            │            │            │
     └────────────┴────────────┴────────────┘
                     Raw Findings
                            │
                            ▼
                  Finding Aggregator
                            │
    ┌──────────────────────────────────────────┐
    │ Normalize Findings                       │
    │ Generate Fingerprints                    │
    │ Remove Duplicate Findings                │
    │ Correlate Vulnerabilities                │
    │ Add Remediation Guidance                 │
    │ Calculate Risk Scores                    │
    │ Map Compliance Standards                 │
    └──────────────────────────────────────────┘
                            │
                            ▼
                   Report Generator
                            │
      ┌────────┬────────┬────────┬─────────┐
      ▼        ▼        ▼        ▼
    HTML      PDF     JSON     SARIF
```

---

# Project Structure

```
AI-DevSecOps-Security-Pipeline/

│
├── agent/
│   ├── orchestrator.py
│   ├── planner.py
│   └── executor_manager.py
│
├── core/
│   ├── finding_aggregator.py
│   ├── findings.py
│   ├── compliance.py
│   ├── remediation.py
│   └── risk.py
│
├── executors/
│   ├── semgrep_executor.py
│   ├── osv_executor.py
│   ├── syft_executor.py
│   ├── grype_executor.py
│   ├── trivy_executor.py
│   └── gitleaks_executor.py
│
├── reporting/
│   ├── report_generator.py
│   ├── html_exporter.py
│   ├── pdf_exporter.py
│   ├── csv_exporter.py
│   ├── json_exporter.py
│   └── sarif_exporter.py
│
├── outputs/
├── reports/
├── logs/
├── tools/
│
├── config.py
├── app.py
├── requirements.txt
└── README.md
```

---

# Configuration

All tool paths are configured inside **config.py**.

Example:

```python
SEMGREP_PATH = "semgrep"

OSV_SCANNER_PATH = "osv-scanner"

SYFT_PATH = "syft"

GRYPE_PATH = "grype"

TRIVY_PATH = "trivy"

GITLEAKS_PATH = "gitleaks"

OUTPUT_DIR = "outputs"

REPORT_DIR = "reports"

LOG_DIR = "logs"
```

Add the path of tools in enviroment variables,If a tool is not available via your system PATH, replace the value with its absolute executable path.

---

# Running the Pipeline

```
python app.py
```

Example

```
Target Repository

D:\juice-shop
```

Pipeline execution:

* Execute all configured scanners
* Aggregate findings
* Normalize vulnerabilities
* Generate fingerprints
* Remove duplicates
* Correlate findings
* Calculate risk score
* Map compliance controls
* Generate reports

---

# Finding Processing Pipeline

```
Raw Findings

↓

Normalization

↓

Fingerprint Generation

↓

Duplicate Removal

↓

Correlation

↓

Risk Score Calculation

↓

Compliance Mapping

↓

Remediation

↓

Report Generation
```

---

# Generated Reports

Reports are generated inside the **reports/** directory.

```
reports/

security-report.html

security-report.pdf

security-report.csv

security-report.json

security-report.sarif
```

---

# Example Console Output

```
=====================================================

AI DevSecOps Security Pipeline

=====================================================

Initializing Pipeline...

Execution Plan

✔ SAST

✔ Dependency Security

✔ Container Security

✔ Secret Detection

-------------------------------------

Collected Findings : 126

Normalized Findings : 101

High : 69

Medium : 29

Low : 3

Generating Reports...

✔ HTML

✔ PDF

✔ JSON

✔ CSV

✔ SARIF

Completed Successfully
```

---

# Sample Report

You can add screenshots inside:

```
docs/images/
```

Example:

```
README Images

├── dashboard.png

├── html-report.png

├── pdf-report.png

└── architecture.png
```

Then reference them:

```markdown
## HTML Report

![HTML Report](docs/images/html-report.png)

## PDF Report

![PDF Report](docs/images/pdf-report.png)
```

---

# CI/CD Integration

The pipeline is designed for easy integration with:

* GitHub Actions
* GitLab CI
* Azure DevOps
* Jenkins
* CircleCI
* Bitbucket Pipelines

Example:

```
Checkout Source

↓

Install Dependencies

↓

Run Security Pipeline

↓

Generate Reports

↓

Upload Reports as Artifacts

↓

Fail Build on High Severity Findings
```

---

# Roadmap

### Current

* Multi-tool orchestration
* SAST
* Dependency scanning
* Container scanning
* Secret detection
* Risk scoring
* Compliance mapping
* Professional reports

### Planned

* AI vulnerability reasoning
* Intelligent remediation
* Patch prioritization
* Repository-aware analysis
* Root cause detection
* Security knowledge graph
* AI security assistant
* Automated fix generation
* Trend analysis
* Interactive dashboard

---

# Contributing

Contributions are welcome.

* Fork the repository
* Create a feature branch
* Commit your changes
* Open a Pull Request

---

# License

Licensed under the MIT License.

---

# Acknowledgements

This project is powered by the open-source security community.

* Semgrep  * OSV Scanner  * Syft   * Grype  * Trivy  * Gitleaks  * Python

---

# Author

**Harsh Tandel**

Security Engineer • DevSecOps • Application Security • AI Security • Smart Contract Security

GitHub: https://github.com/HARSH-21
