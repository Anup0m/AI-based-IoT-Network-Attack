# Complete Project Architecture & Technical Explanation
## AI-Based IoT Network Attack Detection System

**Institution:** Unitedworld Institute of Technology (UIT), Karnavati University  
**Program:** Bachelor of Science (Hons.) in Computer Science  
**Course:** Computer Networks  
**Faculty Guide:** Ms. Pragya Vats  
**Target Environment:** Python 3.10+ / Scikit-Learn / Streamlit / Jupyter  

---

## 1. Executive Summary: What is This Project Actually Doing?

### The Problem in IoT Networks
In smart homes, campus facilities, and industrial environments, thousands of small Internet of Things (IoT) devices (such as CCTV cameras, smart door locks, and temperature sensors) communicate with cloud servers.
- **Normal behavior:** A temperature sensor sends a few small packets every 30–60 seconds using the lightweight **MQTT protocol (Port 1883)**, receives an `ACK` (acknowledgment) from the server, and goes to sleep.
- **Attack behavior:** When an attacker infects an IoT device with malware (such as the famous **Mirai botnet**), the device turns into a "zombie". It starts spamming the network with thousands of connection requests per second (**SYN Flood / Denial of Service attack**) or scans other computers on **Port 23 (Telnet) / Port 22 (SSH)** looking for open vulnerabilities (**Port Scanning**).

### Why Traditional Firewalls Fail
1. **Privacy & Encryption:** Network security tools cannot read the internal data inside encrypted packets (doing so violates privacy laws and breaks SSL/TLS encryption).
2. **IP Spoofing:** Attackers constantly change (spoof) their IP addresses, so a simple rule like "block IP 192.168.1.50" fails immediately.

### Our Solution: Flow-Level AI Intrusion Detection System (IDS)
Instead of inspecting private packet contents, our system inspects the **rhythm and behavioral metadata of the network conversation (called a "network flow")**:
- How fast are packets being transmitted?
- What is the ratio of `SYN` (connection requests) to `ACK` (handshake confirmations)?
- What destination port is being targeted?
- What are the packet length distributions and timing intervals?

Our machine learning model (**Random Forest Classifier**) evaluates these flow patterns in real time to categorize traffic as **`BENIGN` (Normal safe operation)** or **`ATTACK` (Malicious intrusion)** with **97.10% accuracy** and a **False Positive Rate of only 1.79%**.

---

## 2. Complete File-by-File Breakdown

Here is every file in your project, why it exists, what it contains, and how it connects to the system:

```text
c:/Users/Yash/Desktop/CN MINI PROJECT/
├── requirements.txt                    # Python package dependencies
├── README.md                           # Project documentation & execution guide
├── data/
│   └── iot_network_traffic.csv         # 10,000 network flows (dataset)
├── notebooks/
│   └── IoT_Attack_Detection_Model.ipynb # Complete 7-cell ML engineering pipeline
├── artifacts/
│   ├── iot_ids_artifacts.pkl          # Serialized trained model & imputer
│   ├── model_metadata.json            # Academic reproducibility manifest
│   └── ids_model_evaluation.png       # Confusion matrix & feature importance plot
└── src/
    └── app.py                          # Cyber Defense SOC Dashboard (Streamlit UI)
```

---

### Detailed File Analysis:

### 1. `requirements.txt`
* **Purpose:** Declares the exact Python libraries required to run both the machine learning pipeline and the user interface.
* **Libraries Used:**
  * `pandas` & `numpy`: High-performance numerical calculations and tabular data manipulation.
  * `scikit-learn`: The core machine learning engine (implements Decision Trees, Random Forests, train-test splitting, and evaluation metrics).
  * `matplotlib` & `seaborn`: Static evaluation plotting (confusion matrices, feature rankings).
  * `plotly`: Dark-mode interactive cyber visualizations (gauge speedometer, confusion matrix, attribution bars).
  * `joblib`: High-efficiency serialization to save and load trained machine learning models to disk.
  * `streamlit`: The reactive web framework powering the SOC Analyst Dashboard.
  * `jupyterlab` & `ipykernel`: Execution environment for the `.ipynb` notebook.

---

### 2. `data/iot_network_traffic.csv`
* **Purpose:** The network flow dataset used to train and test the AI models.
* **Dataset Scale:** 10,000 distinct network flow records, each containing 16 columns (15 network attributes + 1 `Label` column).
* **Traffic Composition:**
  * **6,415 Benign Flows (65%):** Normal IoT sensor traffic targeting standard ports like Port 1883/8883 (MQTT), Port 80/443 (HTTP/HTTPS), and Port 53 (DNS) with balanced TCP handshakes and low packet rates (~120 pkts/s).
  * **3,585 Attack Flows (35%):** Malicious intrusions simulating volumetric SYN Floods and Port Scans targeting Port 22 (SSH), Port 23 (Telnet), and Port 8080 with high transmission rates (~2,400 pkts/s) and high SYN counts.
  * **Realistic Label Noise:** Injects 2.5% label flipping to simulate real-world network ambiguity.

---

### 3. `notebooks/IoT_Attack_Detection_Model.ipynb`
* **Purpose:** The primary academic and technical deliverable. It contains the complete 7-cell modular pipeline:
  * **Cell 1 (Setup & Imports):** Sets random seeds (`RANDOM_SEED = 42`), configures paths, and defines the 15 network flow attributes.
  * **Cell 2 (Data Ingestion & Synthesis):** Loads `data/iot_network_traffic.csv` or autonomously synthesizes it if missing.
  * **Cell 3 (Privacy & Ethics Safeguards):** Explicitly strips host identifiers (`Source IP`, `Destination IP`, `Timestamp`, `Flow ID`, `MAC`) to prevent host overfitting and protect user privacy. Encodes the target: `0 = Benign`, `1 = Attack`.
  * **Cell 4 (Leakage-Free Splitting):** Splits data into **80% Training (8,000 flows)** and **20% Testing (2,000 flows)** using stratification. Fits a `SimpleImputer(strategy="median")` **strictly on the training data** to eliminate data leakage.
  * **Cell 5 (Model Training):**
    * *Baseline Model:* `DecisionTreeClassifier(max_depth=8)` — transparent rule-based benchmark.
    * *Primary Model:* `RandomForestClassifier(n_estimators=100, max_depth=15, class_weight='balanced')` — ensemble of 100 decision trees.
  * **Cell 6 (Evaluation & FPR Math):** Computes Accuracy, Precision, Recall, F1-Score, and False Positive Rate ($\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$). Generates and saves the confusion matrix and feature importance plots to `artifacts/ids_model_evaluation.png`.
  * **Cell 7 (Artifact Serialization):** Dumps the trained models, imputer, metrics, and test sample into `artifacts/iot_ids_artifacts.pkl`, and exports reproducibility details to `artifacts/model_metadata.json`.

---

### 4. `artifacts/iot_ids_artifacts.pkl`
* **Purpose:** A binary serialized bundle (using Python's `joblib`) containing everything the web dashboard needs to perform real-time threat detection without retraining the model from scratch.
* **Contents Stored Inside:**
  1. `rf_model`: The trained Random Forest classifier.
  2. `dt_model`: The trained Decision Tree baseline classifier.
  3. `imputer`: The fitted `SimpleImputer` ensuring incoming live data is cleaned identically to training data.
  4. `features`: The ordered list of 15 network attribute column names.
  5. `metrics`: All computed benchmark evaluation metrics.
  6. `feature_importances`: Gini importance scores for each network feature.
  7. `sample_test_data`: 200 unseen network flows from the test partition for batch evaluation demos.

---

### 5. `artifacts/model_metadata.json`
* **Purpose:** Academic reproducibility manifest (satisfies university research standards).
* **Contents:**
  * Project Title, Institution (UIT Karnavati University), Faculty Guide (Ms. Pragya Vats).
  * Software versions (`python: 3.14.0`, `scikit_learn: 1.7.2`, `pandas: 2.3.3`, `numpy: 2.3.3`).
  * Train/test split ratio (80/20 Stratified), Random seed (42).
  * Model hyperparameters (`n_estimators: 100`, `max_depth: 15`).
  * Official measured results:
    * **Accuracy:** 97.10%
    * **Precision:** 96.72%
    * **Recall:** 95.09%
    * **F1-Score:** 95.90%
    * **False Positive Rate:** 1.79%

---

### 6. `artifacts/ids_model_evaluation.png`
* **Purpose:** A high-resolution 2-panel technical evaluation graphic:
  * **Left Panel:** The Random Forest Confusion Matrix heatmap showing True Negatives, False Alarms (False Positives), Missed Intrusions (False Negatives), and Caught Attacks (True Positives).
  * **Right Panel:** Horizontal bar chart of the Top 10 Most Predictive Network Flow Features (Gini Importance), proving that TCP flags, transmission rates, and flow duration are the primary indicators of attacks.

---

### 7. `src/app.py`
* **Purpose:** The interactive **Cyber Defense Security Operations Center (SOC) Dashboard**. Built with a dark cyber-defense aesthetic (`#0b0f19` background, neon cyan `#00e5ff`, emerald `#10b981`, and crimson `#ef4444`).
* **The 4 Functional Modules:**
  * **Sidebar:** Live glowing `● SOC MONITOR ACTIVE` status badge, Model switcher (Random Forest vs Decision Tree), Dynamic Sensitivity slider ($0.10$ to $0.90$), and Computer Networks Syllabus Unit tags.
  * **Tab 1 (SOC Performance & Telemetry):** 5 glassmorphism KPI cards, interactive Plotly dark-mode Confusion Matrix with hover tooltips, and Top 8 feature importance bar chart.
  * **Tab 2 (Interactive Flow Simulator & Explainable AI):** 1-Click quick presets (`🟢 Normal MQTT`, `🔴 SYN Flood DoS`, `🟡 Port Scan`), input sliders, a real-time Plotly Speedometer Gauge ($0\text{--}100\%$), an Explainable AI (XAI) feature attribution bar explaining *why* the flow was flagged, and automated firewall remediation advice.
  * **Tab 3 (Batch PCAP Flow Analysis):** File uploader for network CSV captures (with 150-flow test fallback), threat triage summary badges, color-coded security table (`🚨 ATTACK` vs `✅ NORMAL`), and a `📥 Download SOC Incident Report (CSV)` export button.
  * **Tab 4 (Real-Time Network Packet Ticker):** A live streaming packet simulation toggle showing incoming flows from simulated IoT devices, displaying timestamps, ports, flags, and real-time `⚡ FORWARDED` vs `🚫 BLOCKED` SOC firewall actions.

---

### 8. `README.md`
* **Purpose:** The user guide and operational documentation for examiners or students cloning the repository. It outlines the project overview, quickstart installation commands, measured metrics, and syllabus mapping.

---

## 3. The 15 Network Flow Features & Syllabus Alignment

Every single feature processed by the model maps directly to the **UIT Computer Networks Syllabus**:

| Syllabus Unit | Course Topics | Features Extracted & Used in Model |
| :--- | :--- | :--- |
| **Unit I: Application Layer** | Network services, DNS, HTTP, IoT MQTT | `Destination Port`: Differentiates MQTT (1883/8883), HTTP/HTTPS (80/443), DNS (53), Telnet (23), and SSH (22). |
| **Unit II: Transport Layer** | TCP/UDP protocols, handshake flags, flow duration | `SYN Flag Count`, `ACK Flag Count`, `RST Flag Count`, `Protocol` (TCP=6, UDP=17, ICMP=1), `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`. High SYN + 0 ACK flags signal SYN Floods. |
| **Unit III: Network Layer** | IP routing, transmission volume, privacy | `Flow Bytes/s`, `Flow Packets/s`. Evaluates bandwidth consumption without inspecting private packet payload. Host IP addresses are stripped to prevent host overfitting. |
| **Unit IV: Data Link Layer** | Framing, packet length distribution | `Total Length of Fwd Packets`, `Total Length of Bwd Packets`, `Fwd Packet Length Mean`, `Bwd Packet Length Mean`, `Flow IAT Mean` (Inter-Arrival Time). |
| **Unit V: Security & Monitoring** | Intrusion Detection Systems (IDS), anomaly triage | The core Random Forest classification engine, confusion matrix calculation, and False Positive Rate minimization. |

---

## 4. Measured Performance Results

Evaluated on an **unseen test partition of 2,000 flows (20%)**:

```text
========================================================================
METRIC                        BASELINE (DECISION TREE)    PRIMARY (RANDOM FOREST)
========================================================================
Accuracy                      94.65%                      97.10% (Target: >=90%) [PASSED]
Recall (Detection Rate)       91.29%                      95.09% (Target: >=88%) [PASSED]
False Positive Rate (FPR)     3.54%                       1.79%  (Target: <=5%)  [PASSED]
Precision                     93.42%                      96.72%
F1-Score                      92.34%                      95.90%
========================================================================
```

### Why False Positive Rate (FPR) is Critical in Network Security:
- In networking, a **False Positive** means safe IoT telemetry (like a temperature sensor update) was incorrectly flagged as an attack.
- If an IDS has a 15% FPR, the security team gets thousands of false alarms per hour, leading to **alert fatigue** and shutting off the alarm.
- Our model keeps the FPR at **1.79%**, ensuring high security without overwhelming network operators.

---

## 5. How to Run & Demonstrate the Project

### Option A: The Academic Machine Learning Pipeline (Jupyter Notebook)
To run or re-train the model directly in the command line:
```powershell
jupyter nbconvert --to notebook --execute --inplace notebooks/IoT_Attack_Detection_Model.ipynb
```
Or open Jupyter Lab:
```powershell
jupyter lab notebooks/IoT_Attack_Detection_Model.ipynb
```

### Option B: The Cyber Defense SOC Dashboard (Web UI)
To launch the interactive dashboard:
```powershell
streamlit run src/app.py
```
Open your browser at: **`http://localhost:8501`**

---

## 6. Viva Defense Quick Reference Guide (Cheat Sheet)

If the faculty guide (**Ms. Pragya Vats**) or external examiner asks questions during your presentation, here are the exact answers:

* **Q1: Why did you use Random Forest instead of Deep Learning (like CNN/LSTM)?**  
  *Answer:* Network flow metadata consists of structured tabular attributes (packet counts, byte rates, flags). Random Forest trains in seconds, handles skewed distributions without complex scaling, provides direct Gini feature explainability, and achieves >97% accuracy with minimal CPU/memory overhead suitable for edge IoT routers.

* **Q2: Why did you drop IP addresses from training?**  
  *Answer:* If we include IP addresses, the model simply memorizes that "IP 192.168.1.100 is bad". If the attacker changes their IP address by one digit, the model is blind. Dropping IPs forces the model to learn *behavioral patterns* (such as packet bursts and TCP flag anomalies), ensuring true generalization and protecting user privacy.

* **Q3: What is the difference between Precision and Recall in this project?**  
  *Answer:* **Recall** measures how many actual network intrusions were successfully caught (minimizing missed attacks). **Precision** measures what fraction of flagged alarms were genuinely attacks (minimizing false alarms). Both are balanced with an F1-Score of 95.90%.

* **Q4: How does this connect to Computer Networks?**  
  *Answer:* Every single feature represents a header field or metric from the 5 layers of the network stack: Destination Ports (Application Layer), TCP SYN/ACK flags and flow duration (Transport Layer), byte/packet transmission rates (Network Layer), and mean packet lengths (Data Link Layer).
