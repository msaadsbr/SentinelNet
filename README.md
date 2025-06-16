
# 🛡️ SentinelNet

**SentinelNet** is a lightweight, intelligent intrusion detection prototype that flags suspicious network sessions based on real-world traffic features. Inspired by modern IDS tools, it helps identify potentially malicious behavior and provides interpretability behind the detection.

---

## 🔍 Features

- ✅ Detects **Normal** vs **Suspicious** network sessions
- 🧠 Powered by a **Random Forest Classifier**
- 📊 Uses 8 features such as duration, TTL, byte counts, and service type
- 🔍 Displays **attack probability**, **threat level**, and **detailed reasoning**
- 📉 Provides a **visual contribution chart** of the input features
- 🧾 Gives recommended follow-up actions when a session is flagged
- 🖥️ Built with **Python** and **Streamlit**

---

## 🛡️ Why I Built This

While learning network protocols and analyzing traffic in Wireshark, I wanted a simple way to understand when something abnormal was happening on my system.

SentinelNet started as a manual IDS, built for students, analysts, and researchers. It now provides explainable ML detection and I'm working toward a real-time system for non-technical users.

---


## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/msaadsbr/SentinelNet.git
cd SentinelNet
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Add the Model Files

Ensure the following files are placed in the same folder or proper path:

- `rf_model.pkl` — Trained Random Forest model
- `scaler.pkl` — Fitted StandardScaler for input normalization
  

### 4. Run the App

```bash
streamlit run IsAffected/isAffected.py
```

---

## 🧠 How It Works

SentinelNet takes 8 key session-level inputs:

- `dur` – duration of the session
- `sbytes`, `dbytes` – bytes sent/received
- `sttl`, `dttl` – Time-To-Live for packets
- `smean`, `dmean` – average packet size
- `service` – service/protocol used (e.g., HTTP, DNS, FTP)

Then:

1. Normalizes them using a trained `StandardScaler`
2. Predicts if the session is **suspicious** using a trained **Random Forest**
3. Displays:
   - 🧪 **Attack probability**
   - 🟢/🟠/🔴 **Threat level**
   - 🧠 **Heuristic explanation** (e.g., upload imbalance, TTL mismatch)
   - 🧰 **Recommended follow-up actions**
   - 📊 **Feature importance chart**

---

## 📊 Dataset Used

> **UNSW-NB15** — A modern network dataset with normal and attack traffic  
> Includes: Exploits, DoS, Reconnaissance, Backdoors, Fuzzers, etc.  
> [View Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

---

## 🙋 Author

**Muhammad Saad Sabir**    
🔗 https://linkedin.com/in/msaadsbr

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes** only. It is not intended as a full production-grade IDS/IPS.
