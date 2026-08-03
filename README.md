# Anomaly-Based Intrusion Detection System for Healthcare Networks

A capstone project implementing and evaluating an anomaly-based Intrusion Detection System (IDS) for a simulated healthcare network environment, benchmarked against a traditional signature-based IDS (Suricata). Includes a fully functioning real-time detection web application with live alerting, Telegram notifications, and an attack analytics dashboard.

**Author:** Samuel Lau Hao Yi
**Programme:** BSc (Hons) Information Technology (Computer Networking and Security)
**Supervisor:** Dr. Yawar Abbas Bangash

---

## Overview

Healthcare networks are among the most frequently targeted sectors for cyberattacks, yet most intrusion detection deployed today is signature-based — effective against known threats, but blind to zero-day and novel attack behaviour. This project designs, implements, and evaluates an **anomaly-based** approach instead: learning what normal healthcare network traffic looks like, and flagging deviations from it.

The system was built and evaluated inside a fully virtualised healthcare network testbed, using a real ONC-certified EHR platform ([OpenEMR](https://www.open-emr.org/)) as the traffic-generating target, with simulated reconnaissance, credential-based, and enumeration attacks used to construct a labelled dataset for model training and comparison.

## Key Results

Four detection approaches were evaluated under identical conditions:

| Model | Accuracy | Precision | Recall | F1-Score | False Positive Rate |
|---|---|---|---|---|---|
| Z-Score (statistical baseline) | 95.53% | 99.57% | 95.77% | 97.64% | 11.77% |
| Isolation Forest (unsupervised) | 12.45% | 98.23% | 9.58% | 17.47% | 5.00% |
| **Random Forest (supervised)** | **99.33%** | **99.97%** | **99.33%** | **99.65%** | **0.82%** |
| Suricata (signature-based) | 4.34% | 59.28% | 3.25% | 6.17% | 64.41% |

Random Forest, trained on 12 flow-level statistical features with SMOTE class balancing, substantially outperformed both the simpler statistical baseline and the signature-based comparator — most notably achieving a false positive rate over 78x lower than Suricata's, a critical factor for operational viability in a clinical environment where alert fatigue directly risks patient safety.

## Live System

Beyond offline evaluation, the trained Random Forest model was deployed as a continuously running, real-time detection service:

- **Live Detection Dashboard** — real-time flow classification, adjustable confidence/sensitivity thresholds, session export (PCAP + CSV) by timeframe
- **Attack Summary Dashboard** — severity breakdown, protocol distribution, attack-type analytics, top attacker/target rankings, recent critical event log
- **Telegram Alerting** — instant push notifications on detected attacks, including classified attack type and severity
- **Heuristic Attack Classification** — detected attacks are further categorised (Port Scan/Probe, Brute Force, DDoS/Flood, Data Exfiltration, DNS Tunnelling, Slow DoS) based on flow characteristics, for operational readability

The live system was further tested against attack categories **not present in the training dataset** — data exfiltration and denial-of-service (SYN flood, HTTP flood, Slowloris) — to assess behavioural generalisation beyond the specific attack tools used for training.

---

## Architecture

```
External Users → Firewall/DMZ → Internal Healthcare Network
                                        │
                          ┌─────────────┼─────────────┐
                          │             │             │
                    EHR Server    Legitimate      IDS Node
                    (OpenEMR)     Workstation    (passive SPAN
                          │                       capture)
                          │                            │
                    Attacker  ──────────────────────────
                    Workstation
```

The IDS node monitors all network traffic passively via a mirrored (SPAN-style) interface, meaning it observes a full copy of traffic without ever sitting in the critical network path — it cannot degrade application performance or availability by design.

### Lab Environment

| VM Role | OS | Purpose |
|---|---|---|
| Firewall/Router | pfSense CE | Network gateway, routing |
| EHR Server | Ubuntu 22.04 | Hosts OpenEMR (Docker) |
| IDS Node | Ubuntu 22.04 | Passive capture, feature extraction, model inference |
| Legitimate User | Windows 10 | Generates normal clinical traffic |
| Attacker | Kali Linux | Executes simulated attacks |

### Dataset

- **84,639 labelled flows** (2,838 normal / 81,801 attack)
- **12 flow-level features**: duration, packet/byte counts, packet size statistics, inter-arrival time statistics, throughput
- Attack traffic generated via Nmap (SYN/aggressive scan), Hydra (HTTP brute-force), and Dirb (directory enumeration)

---

## Project Structure

```
ids_system/
├── app.py                    # Flask backend — auto-starts live detection on launch
├── detector.py                # Capture engine, RF inference, attack classification, Telegram alerts
├── train_model.py             # Trains Random Forest from labelled dataset
├── test_classifier.py         # Validates attack-type heuristics against the dataset
├── requirements.txt
├── .env.example                # Template for required environment variables
│
├── templates/
│   ├── live.html               # Live Detection dashboard
│   └── summary.html            # Attack Summary analytics dashboard
│
├── attack_scripts/
│   ├── data_exfil_sim.py       # Simulates bulk patient record exfiltration
│   └── dns_exfil_sim.py        # Simulates DNS tunnelling exfiltration
│
├── model/                      # Generated by train_model.py (not committed)
├── sessions/                   # Saved session snapshots (not committed)
└── dataset/                    # Captured/labelled traffic data
```

---

## Setup

### Prerequisites

- Python 3.10+
- A network interface capable of promiscuous-mode packet capture (root/sudo required)
- (Optional) A Telegram bot for alert notifications — see [BotFather](https://t.me/BotFather)

### Installation

```bash
git clone https://github.com/samuerudes/OpenEMR-Anomaly-based-Intrusion-Detection-System
cd ids_system
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration

Copy the environment template and fill in your own values:

```bash
cp .env.example .env
```

```
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

### Train the model

Requires a labelled `combined_dataset.csv` (flow features + `label` column) in `dataset/`:

```bash
python3 train_model.py
```

### Run

Packet capture requires elevated privileges:

```bash
sudo venv/bin/python3 app.py
```

Then visit `http://<ids-node-ip>:5000` — the Attack Summary dashboard loads by default; Live Detection is available at `/live`.

---

## Attack Simulation Scripts

Located in `attack_scripts/`, run from an attacker machine against the target EHR server:

| Script | Simulates |
|---|---|
| `data_exfil_sim.py` | Bulk sequential patient record scraping via an authenticated session (remember to add credentials)|
| `dns_exfil_sim.py` | DNS tunnelling — payload encoded into DNS query subdomains |

Additional attack categories (port scanning, brute-force, DoS) were tested using standard tools: `nmap`, `hydra`, `dirb`, `hping3`, `ab` (ApacheBench), and `slowloris`.

---

## Limitations & Future Work

This evaluation was conducted within a single testbed using one EHR platform and a fixed set of attack tools; results may not generalise directly to other environments without further validation. The live system's detection of attack categories outside the labelled training set (data exfiltration, DoS) is a proof-of-concept demonstration rather than a formally ground-truth-validated result. See the full capstone report for a complete discussion of limitations, including class imbalance effects on unsupervised methods, and directions for future work (multi-platform evaluation, concept drift handling, deep learning architectures, and formally validated attack-type classification).

---

## Acknowledgements

Built using [OpenEMR](https://www.open-emr.org/), [pfSense](https://www.pfsense.org/), [Suricata](https://suricata.io/), [scikit-learn](https://scikit-learn.org/), and [Scapy](https://scapy.net/).