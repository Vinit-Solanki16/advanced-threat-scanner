# Advanced Threat Scanner (ML-Enhanced)

## Abstract
A Python-based security tool designed to detect XSS and Time-Based Blind SQL Injection vulnerabilities. It features an integrated Machine Learning module (Isolation Forest) to identify anomalies in server response times, drastically reducing false negatives in blind injection attacks, alongside an LLM/AI-Agent auditing module.

## Features
- **Reconnaissance:** Automated link extraction and form parsing.
- **Network Scanning:** Top 100 TCP SYN port scanning via Scapy.
- **Concurrent Engine:** Multi-threaded vulnerability scanning for faster execution.
- **ML-Driven Detection:** Unsupervised learning to detect time-based anomalies.
- **AI Agent Auditing:** Payload injection to test LLM Chatbots for Jailbreaks and System Prompt Leakage.
- **Secure Reporting:** AES-128 encryption for vulnerability reports.

## Tech Stack
- Python 3.12
- Scikit-learn (Anomaly Detection)
- Scapy (Network Packets)
- Cryptography (Fernet/AES)
- BeautifulSoup4 (HTML Parsing)
