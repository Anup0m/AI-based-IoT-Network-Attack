import os
import joblib
import numpy as np
import pandas as pd
import streamlit as st

# Configure page
st.set_page_config(
    page_title="IoT Network Attack Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom clean CSS
st.markdown("""
<style>
    .header-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0F172A;
        margin-bottom: 0.1rem;
    }
    .header-subtitle {
        font-size: 1.0rem;
        color: #475569;
        margin-bottom: 1.2rem;
    }
    .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .status-online {
        background-color: #DEF7EC;
        color: #03543F;
    }
    .alert-card-danger {
        background-color: #FEF2F2;
        border-left: 5px solid #EF4444;
        padding: 16px;
        border-radius: 6px;
        margin-top: 10px;
    }
    .alert-card-success {
        background-color: #F0FDF4;
        border-left: 5px solid #22C55E;
        padding: 16px;
        border-radius: 6px;
        margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Path to trained model
ARTIFACT_PATH = os.path.join(os.path.dirname(__file__), "..", "artifacts", "iot_ids_artifacts.pkl")
if not os.path.exists(ARTIFACT_PATH):
    ARTIFACT_PATH = "artifacts/iot_ids_artifacts.pkl"

# Top header
col_title, col_status = st.columns([3, 1])
with col_title:
    st.markdown('<div class="header-title">🛡️ IoT Network Attack Detection System</div>', unsafe_allow_html=True)
    st.markdown('<div class="header-subtitle">Real-time IoT traffic analysis & anomaly inspection | Computer Networks Project</div>', unsafe_allow_html=True)
with col_status:
    st.markdown(
        '<div style="text-align: right; padding-top: 15px;">'
        '<span class="status-badge status-online">● IDS Engine Active</span><br>'
        '<small style="color: #64748B;">Model: Random Forest</small>'
        '</div>',
        unsafe_allow_html=True
    )

if not os.path.exists(ARTIFACT_PATH):
    st.error(f"⚠️ Model artifact `{ARTIFACT_PATH}` not found! Please run the notebook first to train the detection engine.")
    st.stop()

# Load model artifacts (always uses the best model automatically)
artifacts = joblib.load(ARTIFACT_PATH)
model = artifacts.get("rf_model")  # Best performing Random Forest model
imputer = artifacts["imputer"]
features = artifacts["features"]
sample_test_data = artifacts["sample_test_data"]
metrics = artifacts["metrics"]["Random Forest (Primary)"]

# Primary user tabs
tab1, tab2, tab3 = st.tabs([
    "⚡ Live Threat Detector & Simulator",
    "📂 Batch Traffic Capture Scanner",
    "ℹ️ Engine Details & Network Mapping"
])

# -----------------------------------------------------------------------------
# TAB 1: Live Threat Detector & Simulator (Primary User Screen)
# -----------------------------------------------------------------------------
with tab1:
    st.markdown("### Test a Network Traffic Flow")
    st.write("Analyze individual IoT network connections in real time. Choose a pre-set scenario below or customize the traffic parameters.")

    # Quick 1-click test buttons
    st.markdown("**Quick Test Scenarios:**")
    btn_col1, btn_col2, btn_col3, btn_col4 = st.columns(4)
    
    if "flow_preset" not in st.session_state:
        st.session_state["flow_preset"] = "normal_mqtt"

    if btn_col1.button("🟢 Normal MQTT Telemetry", use_container_width=True):
        st.session_state["flow_preset"] = "normal_mqtt"
    if btn_col2.button("🔴 SYN Flood Attack (DoS)", use_container_width=True):
        st.session_state["flow_preset"] = "syn_flood"
    if btn_col3.button("🟠 Port Scan Probe (Mirai)", use_container_width=True):
        st.session_state["flow_preset"] = "port_scan"
    if btn_col4.button("🔄 Reset Parameters", use_container_width=True):
        st.session_state["flow_preset"] = "default"

    preset = st.session_state["flow_preset"]

    # Parameter values based on preset
    if preset == "normal_mqtt":
        init_port, init_proto, init_dur = 1883, 6, 42000
        init_fwd, init_bwd, init_bytes = 8, 7, 15000.0
        init_pkts, init_syn, init_ack = 120.0, 1, 2
        st.info("Loaded **Normal MQTT IoT Telemetry**: Standard sensor data sent to cloud over Port 1883 with completed TCP handshake.")
    elif preset == "syn_flood":
        init_port, init_proto, init_dur = 1883, 6, 11000
        init_fwd, init_bwd, init_bytes = 50, 1, 190000.0
        init_pkts, init_syn, init_ack = 2400.0, 8, 0
        st.warning("Loaded **SYN Flood DoS Attack**: Massive burst of connection requests (8 SYN flags) without ACK confirmations.")
    elif preset == "port_scan":
        init_port, init_proto, init_dur = 23, 6, 4000
        init_fwd, init_bwd, init_bytes = 35, 0, 140000.0
        init_pkts, init_syn, init_ack = 1800.0, 5, 0
        st.warning("Loaded **Port Scan Probe**: Rapid connection attempts on Telnet (Port 23) probing for open vulnerabilities.")
    else:
        init_port, init_proto, init_dur = 1883, 6, 35000
        init_fwd, init_bwd, init_bytes = 8, 6, 14000.0
        init_pkts, init_syn, init_ack = 110.0, 1, 2

    # Flow input controls
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**1. Protocol & Target**")
        port = st.selectbox("Destination Port", [1883, 8883, 80, 443, 22, 23, 53, 8080], 
                            index=[1883, 8883, 80, 443, 22, 23, 53, 8080].index(init_port))
        proto = st.selectbox("Transport Protocol", [6, 17, 1], 
                             format_func=lambda x: "TCP (6)" if x==6 else ("UDP (17)" if x==17 else "ICMP (1)"),
                             index=[6, 17, 1].index(init_proto))
        dur = st.number_input("Flow Duration (μs)", value=int(init_dur), step=1000)

    with col2:
        st.markdown("**2. Volume & Packets**")
        fwd_p = st.slider("Forward Packets", 1, 150, int(init_fwd))
        bwd_p = st.slider("Backward Packets", 0, 150, int(init_bwd))
        b_rate = st.number_input("Bytes per Second", value=float(init_bytes), step=2000.0)

    with col3:
        st.markdown("**3. Transmission Rates & Flags**")
        p_rate = st.number_input("Packets per Second", value=float(init_pkts), step=20.0)
        syn_c = st.slider("SYN Flags Count", 0, 15, int(init_syn), help="High SYN with 0 ACK indicates SYN Flooding")
        ack_c = st.slider("ACK Flags Count", 0, 10, int(init_ack), help="Normal TCP connections always include ACK responses")

    # Run inference
    input_df = pd.DataFrame([{
        "Destination Port": port,
        "Protocol": proto,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd_p,
        "Total Backward Packets": bwd_p,
        "Total Length of Fwd Packets": fwd_p * 75.0,
        "Total Length of Bwd Packets": bwd_p * 110.0,
        "Fwd Packet Length Mean": 75.0,
        "Bwd Packet Length Mean": 110.0,
        "Flow Bytes/s": b_rate,
        "Flow Packets/s": p_rate,
        "Flow IAT Mean": max(1.0, dur / max(1, (fwd_p + bwd_p))),
        "SYN Flag Count": syn_c,
        "ACK Flag Count": ack_c,
        "RST Flag Count": 0,
    }])[features]

    pred = model.predict(input_df)[0]
    attack_risk = model.predict_proba(input_df)[0][1]

    # Display Verdict
    st.markdown("---")
    res_col1, res_col2 = st.columns([1.2, 2])

    with res_col1:
        if pred == 1:
            st.error(f"### 🚨 ATTACK DETECTED\n**Attack Probability: {attack_risk * 100:.1f}%**")
        else:
            st.success(f"### ✅ BENIGN / NORMAL\n**Normal Probability: {(1 - attack_risk) * 100:.1f}%**")
        st.progress(float(attack_risk))

    with res_col2:
        if pred == 1:
            st.markdown(f"""
            <div class="alert-card-danger">
                <strong>Threat Analysis & Recommended Action:</strong><br>
                • <strong>Anomaly Triggered:</strong> Elevated transmission rate ({p_rate:.0f} pkts/s) with unbalanced handshake flags (SYN: {syn_c}, ACK: {ack_c}).<br>
                • <strong>Target Port:</strong> {port} ({'MQTT IoT Broker' if port in [1883, 8883] else 'Web/Telnet Service'}).<br>
                • <strong>Action:</strong> Throttle incoming connection requests from this source and trigger firewall rate-limit rule.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="alert-card-success">
                <strong>Clean Flow Confirmation:</strong><br>
                • <strong>Traffic Character:</strong> Valid IoT protocol flow with completed handshake and baseline traffic volumes.<br>
                • <strong>Action:</strong> Allow traffic through gateway with no intervention required.
            </div>
            """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# TAB 2: Batch Traffic Capture Scanner
# -----------------------------------------------------------------------------
with tab2:
    st.markdown("### Scan Traffic Capture Files")
    st.write("Audit packet capture exports or inspect the current test partition of IoT flows.")

    uploaded_file = st.file_uploader("Upload Network Flow CSV (optional)", type=["csv"])
    if uploaded_file is not None:
        batch_df = pd.read_csv(uploaded_file)
        batch_df.columns = batch_df.columns.str.strip()
        eval_features = [c for c in features if c in batch_df.columns]
        X_batch = pd.DataFrame(imputer.transform(batch_df[eval_features]), columns=features)
    else:
        st.caption("Displaying 100 live flows from the unseen test partition:")
        X_batch = sample_test_data[features].iloc[:100].copy()

    batch_preds = model.predict(X_batch)
    batch_probs = model.predict_proba(X_batch)[:, 1]

    # Metrics overview
    total_flows = len(X_batch)
    attack_flows = int(np.sum(batch_preds == 1))
    clean_flows = total_flows - attack_flows

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Flows Inspected", total_flows)
    m2.metric("Intrusions Found", attack_flows)
    m3.metric("Normal Flows", clean_flows)
    threat_pct = (attack_flows / total_flows) * 100 if total_flows > 0 else 0
    m4.metric("Threat Percentage", f"{threat_pct:.1f}%")

    # Table formatting
    results_table = X_batch.copy()
    verdicts = ["🚨 ATTACK" if p == 1 else "✅ NORMAL" for p in batch_preds]
    risk_scores = [f"{prob * 100:.1f}%" for prob in batch_probs]
    results_table.insert(0, "Verdict", verdicts)
    results_table.insert(1, "Attack Risk", risk_scores)

    # Filter
    filter_val = st.radio("Display:", ["All Flows", "Attacks Only", "Normal Only"], horizontal=True)
    if filter_val == "Attacks Only":
        display_df = results_table[results_table["Verdict"].str.contains("ATTACK")]
    elif filter_val == "Normal Only":
        display_df = results_table[results_table["Verdict"].str.contains("NORMAL")]
    else:
        display_df = results_table

    st.dataframe(display_df, use_container_width=True)

    # Download report
    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Inspection Report (CSV)",
        data=csv_bytes,
        file_name="ids_threat_inspection_report.csv",
        mime="text/csv"
    )

# -----------------------------------------------------------------------------
# TAB 3: Engine Details & Network Mapping
# -----------------------------------------------------------------------------
with tab3:
    st.markdown("### Detection Engine Specifications")
    st.write("Technical validation metrics and Computer Networks curriculum alignment.")

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Model Architecture", "Random Forest")
    kpi2.metric("Detection Accuracy", f"{metrics['Accuracy'] * 100:.2f}%")
    kpi3.metric("Recall (Detection Rate)", f"{metrics['Recall (Detection Rate)'] * 100:.2f}%")
    kpi4.metric("False Positive Rate (FPR)", f"{metrics['False Positive Rate (FPR)'] * 100:.2f}%")

    st.markdown("---")
    st.markdown("#### Computer Networks Syllabus Alignment (Units I–V)")
    st.markdown("""
    | Syllabus Unit | Course Topics | Implementation in This Model |
    | :--- | :--- | :--- |
    | **Unit I: Application Layer** | DNS, HTTP, MQTT, Network Services | Inspects `Destination Port` (Port 1883/8883 for MQTT, Port 80/443 for Web). |
    | **Unit II: Transport Layer** | TCP/UDP protocols, handshake flags, flow duration | Analyzes `SYN`, `ACK`, and `RST` flag counts, duration, and packet counters. |
    | **Unit III: Network Layer** | IP addressing, routing, traffic volume | Evaluates bidirectional transmission rates (`Flow Bytes/s`, `Flow Packets/s`). Host IPs stripped for privacy. |
    | **Unit IV: Data Link Layer** | Framing, packet lengths | Monitors packet size distributions (`Fwd Packet Length Mean`, `Bwd Packet Length Mean`). |
    | **Unit V: Security & Monitoring** | Intrusion Detection Systems (IDS) | Core deliverable: automated AI-driven network anomaly classifier. |
    """)
