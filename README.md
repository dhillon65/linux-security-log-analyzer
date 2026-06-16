# linux-security-log-analyzer

## Overview

Linux Security Log Analyzer & Threat Detection System is a cybersecurity-focused Python project designed to analyze Linux authentication logs, detect suspicious activities, identify brute-force attacks, calculate threat scores, and generate security reports.

This project demonstrates practical skills in:

* Cybersecurity
* Linux Administration
* Digital Forensics
* Incident Response
* Threat Detection
* Python Automation
* Log Analysis

---

## Features

### Log Analysis

* Parse Linux authentication logs
* Detect failed login attempts
* Detect successful logins
* Extract usernames and IP addresses

### Threat Detection

* Brute-force attack detection
* Suspicious IP identification
* Threat score calculation
* Severity classification

### Report Generation

* CSV Reports
* JSON Reports
* PDF Reports
* Security Summary Reports

### Visualization

* Threat distribution charts
* Top attacker analysis
* Dashboard integration

### Dashboard

* Flask-based web dashboard
* Security statistics
* Threat overview
* Report visualization

---

## Project Structure

linux-log-analyzer/

├── analyzer/

├── config/

├── dashboard/

├── data/

├── generators/

├── reports/

├── tests/

├── utils/

├── main.py

├── requirements.txt

├── Dockerfile

└── README.md

---

## Technologies Used

### Programming Language

* Python 3

### Libraries

* Flask
* Matplotlib
* ReportLab
* Pytest
* Pandas

### Security Concepts

* Log Analysis
* Threat Intelligence
* Brute Force Detection
* Digital Forensics
* Security Monitoring

---

## Installation

Clone Repository

git clone https://github.com/dhillon65/linux-security-log-analyzer


cd linux-log-analyzer

Install Dependencies

pip install -r requirements.txt

---

## Running the Analyzer

python main.py

---

## Running the Dashboard

python dashboard/app.py

Open Browser:

http://127.0.0.1:5000

---

## Generated Reports

CSV Report

reports/csv/security_report.csv

JSON Report

reports/json/security_report.json

PDF Report

reports/pdf/security_report.pdf

Charts

reports/charts/

---

## Sample Workflow

Load Log File

↓

Parse Events

↓

Detect Failed Logins

↓

Detect Brute Force Attacks

↓

Calculate Threat Scores

↓

Generate Reports

↓

Visualize Results

---

## Threat Severity Levels

| Score | Severity |
| ----- | -------- |
| 0-29  | LOW      |
| 30-59 | MEDIUM   |
| 60-99 | HIGH     |
| 100+  | CRITICAL |

---

## Example Output

Top Suspicious IPs

192.168.1.100

Score: 135

Severity: CRITICAL

10.0.0.15

Score: 80

Severity: HIGH

172.16.1.20

Score: 45

Severity: MEDIUM

---

## Future Enhancements

* Real-time log monitoring
* Email alerts
* SIEM integration
* Elasticsearch support
* Threat intelligence feeds
* Docker deployment
* Cloud deployment
* Machine Learning based anomaly detection

---

## Learning Outcomes

This project demonstrates knowledge of:

* Python Development
* Cybersecurity Operations
* Linux Log Analysis
* Security Monitoring
* Incident Response
* Threat Detection
* Report Generation
* Dashboard Development

---

## Author

Satnam Singh

B.Tech Computer Science & Engineering

Cybersecurity Enthusiast

Punjab, India

---

## License

This project is intended for educational and cybersecurity learning purposes only.
