# AI-Based IoT Network Attack Detection

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange.svg)](https://scikit-learn.org/)

**Institution:** Unitedworld Institute of Technology (UIT), Karnavati University  
**Program:** Bachelor of Science (Hons.) in Computer Science  
**Course:** Computer Networks  
**Faculty Guide:** Ms. Pragya Vats  

---

## 📌 Project Overview

This project implements an AI-driven Intrusion Detection System (IDS) tailored for Internet of Things (IoT) network environments. By analyzing network flow header metadata—rather than inspecting sensitive packet payloads—the system classifies traffic as either **BENIGN (Normal)** or an **ATTACK (Intrusion/Anomaly)** such as Port Scans, SYN Floods, or DoS attacks.

### Key Highlights:
- **Computer Networks Syllabus Alignment:** All 15 flow attributes directly map across the 5 core units of the UIT Computer Networks syllabus (Application, Transport, Network, Data Link, and Security layers).
- **Privacy & Ethics Preservation:** Host identifiers (Source/Destination IP, Timestamp, Flow ID, MAC addresses) are stripped to avoid PII exposure and host overfitting.
- **Leakage-Free ML Pipeline:** Stratified 80/20 train/test split with median imputation fitted exclusively on the training partition.
- **High Detection Performance:** Random Forest classifier achieves **>97% Accuracy**, **>95% Recall**, and **<1.8% False Positive Rate (FPR)**.
- **Interactive Streamlit Web Dashboard:** 3-tab prototype featuring performance metrics with confusion matrix, batch CSV flow inspection with risk scoring, and real-time interactive IoT flow simulation.

---

## 📁 Repository Structure

```
.
├── requirements.txt                    # Project Python dependencies
├── README.md                           # Quickstart & documentation
├── data/
│   └── iot_network_traffic.csv         # Generated synthetic or real CIC-IDS2017 dataset (10,000 flows)
├── notebooks/
│   └── IoT_Attack_Detection_Model.ipynb # Primary ML notebook (7 modular cells)
├── artifacts/
│   ├── iot_ids_artifacts.pkl          # Serialized models, imputer, metrics & test sample
│   ├── model_metadata.json            # Reproducibility manifest
│   └── ids_model_evaluation.png       # Confusion matrix & feature importance plots
└── src/
    └── app.py                          # Streamlit 3-tab interactive web dashboard
```

---

## ⚙️ Quickstart & Setup

### 1. Environment Installation
Ensure you have Python 3.10+ installed. Install the dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the Jupyter Notebook
To execute all 7 modular cells, train the baseline and primary models, and export artifacts:
```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/IoT_Attack_Detection_Model.ipynb
```

### 3. Launch the Streamlit Web Application
Run the interactive dashboard:
```bash
streamlit run src/app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 📊 Measured Model Performance

Evaluated on an unseen 20% test partition (2,000 network flows):

| Metric | Baseline (Decision Tree) | Primary (Random Forest) | Acceptance Threshold |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 94.65% | **97.10%** | $\ge 90.0\%$ |
| **Precision** | 93.42% | **96.72%** | — |
| **Recall (Detection Rate)** | 91.29% | **95.09%** | $\ge 88.0\%$ |
| **F1-Score** | 92.34% | **95.90%** | — |
| **False Positive Rate (FPR)** | 3.54% | **1.79%** | $\le 5.0\%$ |

---

## 🌐 Computer Networks Syllabus Alignment

| Syllabus Unit | Course Topics | Implementation in This Model |
| :--- | :--- | :--- |
| **Unit I: Application Layer** | Network services, DNS, HTTP, MQTT | Inspects destination ports for IoT application protocols (Port 1883/8883 for MQTT, Port 80/443 for HTTP/HTTPS, Port 53 for DNS). |
| **Unit II: Transport Layer** | TCP/UDP protocols, port numbers, flow duration, packet counts | Analyzes transport protocol flags (`SYN`, `ACK`, `RST`), flow duration, and total forward/backward packet counts. |
| **Unit III: Network Layer** | IP addressing, routing, forwarding, traffic flow direction | Examines bidirectional flow metrics (forward vs. backward transmission volume and byte rates). Raw IP addresses are stripped to ensure model generalization. |
| **Unit IV: Data Link Layer** | Framing, link communication, packet lengths | Analyzes packet size distributions (`Fwd Packet Length Mean`, `Bwd Packet Length Mean`) and inter-arrival timing (`Flow IAT Mean`). |
| **Unit V: Security & Monitoring** | Intrusion detection systems (IDS), operational security | AI-driven anomaly and signature detection engine automating first-pass security reviews. |
