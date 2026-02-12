# cross-platform-threat-mitigator
AI-powered SOAR framework bridging Windows &amp; Kali Linux. Uses Isolation Forest (ML) on Windows to detect live network anomalies and triggers automated incident response on Kali via SSH. Features remote process neutralization, automated forensic logging (last_scan.txt), and rapid vulnerability triaging. 🧠⚔️
To make your GitHub repository stand out to recruiters and the cybersecurity community, your README needs to be scannable, professional, and visually structured.


# 🛡️ Cross-Platform Threat Mitigator

## 📖 Project Overview

**Cross-Platform Threat Mitigator** is an autonomous **SOAR-lite** (Security Orchestration, Automation, and Response) framework. It bridges the gap between Windows-based network monitoring and Linux-based incident response. The system uses Machine Learning to detect anomalies in real-time on a Windows node and automatically executes mitigation scripts on a remote Kali Linux target via secure SSH orchestration.

---

## 🚀 Key Features

* **AI-Powered Detection:** Uses an **Isolation Forest (Unsupervised ML)** model to identify zero-day network threats without relying on signatures.
* **Cross-Platform Orchestration:** Seamlessly connects Windows (Detection) to Kali Linux (Action) using the **Paramiko** SSH library.
* **Automated Mitigation:** Instantly terminates malicious Process IDs (PIDs) on the target system to prevent data exfiltration.
* **Forensic Auditing:** Automatically generates a `last_scan.txt` artifact and runs a vulnerability triage script (`kali_vuln_scanner.sh`) during the incident.

---

## 🛠️ System Architecture

| Component | Technology Stack | Responsibility |
| --- | --- | --- |
| **Detection Brain** | Python, Scapy, Scikit-Learn | Live sniffing & Anomaly detection (Windows) |
| **Communication Layer** | SSH (Paramiko), .env | Secure remote command execution |
| **Tactical Unit** | Bash, Python, Linux SysAdmin | Process killing & Vulnerability scanning (Kali) |

---

## 📁 Repository Structure

```text
cross-platform-threat-mitigator/
├── windows_brain/           # AI Detection logic (Windows)
│   └── app_ai_detector.py
├── tactical_kali/           # Mitigation & Triage (Linux)
│   ├── incidentmanager.py
│   └── kali_vuln_scanner.sh
├── .gitignore               # Security filter for sensitive files
├── LICENSE                  # MIT License
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation

```

---

## ⚙️ Installation & Setup

1. **Clone the Repository:**
```bash
git clone https://github.com/aditidutta696-dev/cross-platform-threat-mitigator.git
cd cross-platform-threat-mitigator

```


2. **Install Dependencies:**
```bash
pip install -r requirements.txt

```


3. **Configure Environment:**
Create a `.env` file in the root directory:
```text
KALI_IP=192.168.x.x
KALI_USER=kali
KALI_PASS=your_password

```



---

## 🗺️ Future Roadmap

Web Dashboard: Developing a Flask-based UI to provide real-time visualization of network traffic patterns and live AI confidence scores.

Multi-Node Orchestration: Scaling the "Detection Brain" to manage and mitigate threats across a fleet of multiple Linux endpoints simultaneously.

Deep Packet Inspection (DPI): Moving beyond header analysis to inspect packet payloads for more granular threat classification using Recurrent Neural Networks (RNNs).
---

## 📜 License & Disclaimer

This project is licensed under the **MIT License**.

> **⚠️ Disclaimer:** This tool is for **educational and authorized security research purposes only**. Never run these scripts on networks or systems without explicit permission. The author is not responsible for any misuse or damage caused by this software.

---

**Now that your README is ready, would you like me to help you create a "Demo" section with sample terminal output to show exactly what the AI sees when it detects an attack?**
