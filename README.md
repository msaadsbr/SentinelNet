
# 🛡️ SentinelNet

**SentinelNet** is a lightweight, intelligent, machine learning-powered tool for detecting suspicious or malicious network sessions. Inspired by modern Intrusion Detection Systems (IDS), it analyzes key features of a session and tells you whether it’s safe or suspicious — in real-time.

---

## 🔍 Features

- ✅ Detects **Normal vs Attack** traffic from session features
- 🧠 Uses a trained **Random Forest** model on the UNSW-NB15 dataset
- ⚙️ Takes in only 8 human-friendly input fields
- 🚨 Provides clear reasons when traffic looks suspicious
- 🖥️ Runs locally via **Streamlit**
- 🔒 Model files are excluded from GitHub for security

---

## 🚀 How to Run

### 1. Clone the Repository

```
git clone https://github.com/msaadsbr/SentinelNet.git
cd SentinelNet
```

### 2. Install Dependencies

```
pip install -r requirements.txt
```

### 3. Add Local Model Files

Place the following files in the `isAffected/` folder (or update the path if you changed it):
- `rf_model.pkl` – trained Random Forest model
- `scaler.pkl` – StandardScaler for input normalization

### 4. Run the App

```
python3 -m streamlit run IsAffected/isAffected.py
```

---

## 🧠 How It Works

The app takes 8 session-level input fields:

- Duration of connection (`dur`)
- Bytes sent and received (`sbytes`, `dbytes`)
- TTL values (`sttl`, `dttl`)
- Average packet sizes (`smean`, `dmean`)
- Protocol/service used (`service`)

These are passed through a scaler, then into a Random Forest model to predict:
- ✅ **Normal** (safe session)
- 🚨 **Attack Detected** (suspicious behavior)

It also provides hints like:
- "High outgoing traffic with little response – possible data exfiltration"
- "Very short session and few packets – might be scanning"

---

## 📊 Dataset Used

> **UNSW-NB15** – Modern cybersecurity dataset for normal and attack traffic. Includes DoS, Exploits, Reconnaissance, etc.
> [https://research.unsw.edu.au/projects/unsw-nb15-dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

---

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. It does not replace enterprise-grade security tools.
