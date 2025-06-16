import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt

# Load model and scaler
base = os.path.dirname(os.path.dirname(__file__)) if "__file__" in globals() else os.getcwd()
model = joblib.load('rf_model.pkl')
scaler = joblib.load('scaler.pkl')

# Title & Layout
st.set_page_config(page_title="SentinelNet", page_icon="\U0001F6E1️")
st.title("\U0001F6E1️ SentinelNet")
st.subheader("Real-Time Network Session Attack Detection")
st.markdown("This tool uses Machine Learning to classify a network session as **normal** or **suspicious** based on 8 key features.")

st.info("""
ℹ️ To use SentinelNet:
- You can manually enter session-level info (duration, bytes, TTL, etc.)
- Or click **'Use Sample Input'** to simulate a real session
- You can get real values from tools like **Wireshark, Netstat, Suricata, Zeek, or log files**
""")

# Set default input values
default_input = {
    "dur": 30.0,
    "sbytes": 6000,
    "dbytes": 6010,
    "sttl": 30,
    "dttl": 35,
    "smean": 350,
    "dmean": 600,
    "service": 'ftp'
}

use_sample = st.checkbox("\U0001F4CA Use Sample Input", value=True)

# UI inputs
dur = st.slider("\U0001F552 Duration of connection (seconds)", 0.0, 1500.0, default_input["dur"] if use_sample else 0.0)
sbytes = st.slider("\U0001F4E4 Bytes sent from your device (sbytes)", 0, 50000, default_input["sbytes"] if use_sample else 0, step=100)
dbytes = st.slider("\U0001F4E5 Bytes received by your device (dbytes)", 0, 50000, default_input["dbytes"] if use_sample else 0, step=100)
sttl = st.slider("\u23F1\uFE0F Source TTL (sttl)", 0, 255, default_input["sttl"] if use_sample else 0)
dttl = st.slider("\u23F1\uFE0F Destination TTL (dttl)", 0, 255, default_input["dttl"] if use_sample else 0)
smean = st.slider("\U0001F4E6 Avg packet size sent (smean)", 0, 1500, default_input["smean"] if use_sample else 0)
dmean = st.slider("\U0001F4E6 Avg packet size received (dmean)", 0, 1500, default_input["dmean"] if use_sample else 0)
service = st.selectbox("\U0001F310 Protocol/Service used", ['-', 'http', 'ftp', 'dns', 'smtp', 'ssh', 'ssl'],
                       index=['-', 'http', 'ftp', 'dns', 'smtp', 'ssh', 'ssl'].index(default_input["service"]) if use_sample else 0)

# Encode service
service_mapping = {'-': 0, 'dns': 1, 'ftp': 2, 'http': 3, 'smtp': 4, 'ssh': 5, 'ssl': 6}
service_encoded = service_mapping.get(service, 0)

# Prepare features for model
input_df = pd.DataFrame([[dur, sbytes, dbytes, sttl, dttl, smean, dmean, service_encoded]],
                        columns=['dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'smean', 'dmean', 'service'])
scaled_input = scaler.transform(input_df)

# Analyze Button
if st.button("\U0001F50D Analyze Session"):
    proba = model.predict_proba(scaled_input)[0][1]  # Probability of being an attack
    result = model.predict(scaled_input)[0]
    reasons = []

    # Heuristic explanations
    if dur < 20 and sbytes < 500 and dbytes < 500:
        reasons.append("Very short session with low data — could be reconnaissance or scanning.")
    if dur > 600 and sbytes > 2000 and dbytes < 300:
        reasons.append("Long duration with low response — may indicate a Denial-of-Service attempt.")
    if sbytes > 4000 and dbytes < 200:
        reasons.append("High outbound traffic with almost no reply — potential data exfiltration.")
    if smean > 1000:
        reasons.append("Unusually large packets sent — could be exploit or flooding.")
    if abs(sttl - dttl) > 32:
        reasons.append("TTL mismatch suggests possible spoofing or asymmetric routing.")
    if sbytes > dbytes * 4:
        reasons.append("Significant upload imbalance — potential data exfiltration.")
    if dur > 1000 and smean < 100:
        reasons.append("Very long connection with small packets — may indicate beaconing.")

    # Threat Level
    if proba > 0.85 :
        threat_level = "🔴 HIGH RISK"
    elif proba > 0.5 :
        threat_level = "🟠 MODERATE RISK"
    else:
        threat_level = "🟢 LOW RISK"


    st.markdown(f"\U0001F52A **Attack Probability:** `{proba:.2%}`")
    st.markdown(f"**Threat Level:** {threat_level}")

    # Outcome
    if result == 0 and not reasons:
        st.success("✅ This network session appears safe (Normal Traffic).")
        st.markdown("**Summary:** The session characteristics are consistent with typical user behavior.")
    else:
        st.error("\U0001F6A8 Suspicious Network Session Detected!")
        if reasons:
            st.warning("\U0001F9E0 Possible Reason(s):")
            for r in reasons:
                st.write(f"- {r}")
        else:
            st.info("⚠️ The session shares behavioral traits with known attack traffic.")

        # Recommendations
        st.subheader("\U0001F6E0️ Recommended Response")
        st.markdown("""
        - 🚫 **Isolate the source device** if behavior persists
        - 🔍 **Review firewall and IDS logs** for related anomalies
        - 📦 **Capture and inspect packets** with Wireshark or Zeek
        - 🧾 **Log this session** and correlate with historical traffic
        """)

    # Visualization
    st.subheader("\U0001F4C8 Feature Contribution Overview")
    input_df_normalized = pd.DataFrame(scaled_input, columns=input_df.columns)
    st.bar_chart(input_df_normalized.T)

# Footer
st.markdown("---")
st.caption("Powered by ML & Streamlit -- msaadsbr")
