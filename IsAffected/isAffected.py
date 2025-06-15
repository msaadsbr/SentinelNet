import streamlit as st
import pandas as pd
import numpy as np
import joblib

# Load model and scaler
model = joblib.load("rf_model.pkl")
scaler = joblib.load("scaler.pkl")

# Page Setup
st.set_page_config(page_title="Network Attack Detector", page_icon="🚨")
st.title("🚨 Network Attack Detection")
st.subheader("Check if a network session is safe or suspicious")

st.write("Fill in the connection details to get a real-time attack prediction.")

# User Inputs (expert mode only)
dur = st.slider("🕒 Duration (seconds)", 0.0, 1000.0, 10.0)
sbytes = st.slider("📤 Bytes sent by source", 0, 5000, 300)
dbytes = st.slider("📥 Bytes received by destination", 0, 5000, 300)
sttl = st.slider("⏱️ Source TTL", 0, 255, 64)
dttl = st.slider("⏱️ Destination TTL", 0, 255, 64)
smean = st.slider("📦 Avg packet size sent", 0, 1500, 300)
dmean = st.slider("📦 Avg packet size received", 0, 1500, 300)

# Build input
user_input = pd.DataFrame([[dur, sbytes, dbytes, sttl, dttl, smean, dmean]],
    columns=['dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'smean', 'dmean'])

scaled_input = scaler.transform(user_input)

# Predict
if st.button("🔍 Check My Connection"):
    result = model.predict(scaled_input)[0]

    if result == 0:
        st.success("✅ This connection appears safe (Normal Traffic).")
    else:
        st.error("🚨 Potential Attack Detected!")

        # Guess likely attack type based on rules
        possible_types = []

        if dur < 10 and sbytes < 500 and dbytes < 500 and sttl > 50:
            possible_types.append("Reconnaissance (scanning or probing)")
        if dur > 600 and sbytes > 2000 and dbytes < 100:
            possible_types.append("DoS (Denial of Service)")
        if sbytes > 4000 and dbytes < 200:
            possible_types.append("Data Exfiltration or Botnet")
        if smean > 1000:
            possible_types.append("Exploitation or Flood attack")

        if possible_types:
            st.warning("🧠 Likely Attack Type(s):")
            for attack in possible_types:
                st.write(f"- ⚠️ {attack}")
        else:
            st.info("⚠️ This session matches patterns of known attacks.")

# Footer
st.markdown("---")
st.markdown("Made with ❤️ by **Muhammad Saad Sabir** — Powered by ML & Streamlit")
