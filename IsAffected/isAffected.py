import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os

# Load model and scaler
base = os.path.dirname(os.path.dirname(__file__)) if "__file__" in globals() else os.getcwd()
model = joblib.load('rf_model.pkl')
scaler = joblib.load('scaler.pkl')

st.set_page_config(page_title="SentinelNet - Network Attack Detector", page_icon="🛡️")
st.title("🛡️ SentinelNet")
st.subheader("Intelligent Intrusion Detection using Machine Learning")

st.markdown("Enter the network session details below to analyze if it's **Normal** or **Suspicious**.")

# ----------------------- INPUTS -----------------------

dur = st.slider("🕒 Duration of connection (seconds)", min_value=0.0, max_value=1500.0, value=60.0, help="How long the connection lasted")

sbytes = st.slider("📤 Bytes sent from your device (sbytes)", 0, 50000, 1000, step=100, help="Total data your device sent during the session")

dbytes = st.slider("📥 Bytes received by your device (dbytes)", 0, 50000, 3000, step=100, help="Total data your device received")

sttl = st.slider("⏱️ Source TTL (sttl)", 0, 255, 64, help="Time-To-Live value for packets from your system")

dttl = st.slider("⏱️ Destination TTL (dttl)", 0, 255, 64, help="TTL for packets from the server you connected to")

smean = st.slider("📦 Average packet size sent (smean)", 0, 1500, 300, help="Estimated average size of packets you sent")

dmean = st.slider("📦 Average packet size received (dmean)", 0, 1500, 400, help="Estimated average packet size received")

service = st.selectbox("🌐 Service/Protocol used", ['-', 'http', 'ftp', 'dns', 'smtp', 'ssh', 'ssl'], help="Type of protocol used in the connection")

# ----------------------- ENCODING -----------------------

# Encode service manually (assuming it was LabelEncoded during training)
service_mapping = {'-': 0, 'dns': 1, 'ftp': 2, 'http': 3, 'smtp': 4, 'ssh': 5, 'ssl': 6}
service_encoded = service_mapping.get(service, 0)

# Final input array (match training order)
features = pd.DataFrame([[dur, sbytes, dbytes, sttl, dttl, smean, dmean, service_encoded]],
    columns=['dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'smean', 'dmean', 'service'])

# Scale input
scaled_input = scaler.transform(features)

# ----------------------- PREDICT -----------------------

if st.button("🔍 Analyze Connection"):
    prediction = model.predict(scaled_input)[0]

    if prediction == 0:
        st.success("✅ This session appears safe (Normal Traffic).")
    else:
        st.error("🚨 Suspicious activity detected! This may be an attack.")
        st.warning("🧠 Suggestion: Check for unauthorized access, scan attempts, or bot traffic.")

# ----------------------- FOOTER -----------------------

st.markdown("---")
st.caption("Made with ❤️ by **Muhammad Saad Sabir** | Powered by ML & Streamlit")
