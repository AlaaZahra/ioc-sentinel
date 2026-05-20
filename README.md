<div align="center">



\# 🛡️ IOC Sentinel



\### Predictive Threat Intelligence \& Real-Time Intrusion Detection



\[!\[Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge\&logo=python\&logoColor=white)](https://python.org)

\[!\[Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge\&logo=streamlit\&logoColor=white)](https://streamlit.io)

\[!\[scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-F7931E?style=for-the-badge\&logo=scikit-learn\&logoColor=white)](https://scikit-learn.org)

\[!\[License](https://img.shields.io/badge/License-MIT-00C48C?style=for-the-badge)](LICENSE)



\*\*How do you detect a cyberattack from an IP that has never been blacklisted before?\*\*



\*IOC Sentinel answers that question.\*



</div>



\---



\## The Problem



Traditional intrusion detection relies on static IP blacklists. If an attacker rotates to a fresh IP — one that's never been reported — they slip right through. This is the \*\*zero-day IP problem\*\*, and it's one of the main reasons behavioral detection has become essential alongside reputation-based approaches.



IOC Sentinel tackles this by combining two layers:



1\. \*\*Static threat intelligence\*\* — checks incoming IPs against live feeds. Known bad actors get blocked instantly.

2\. \*\*Behavioral AI\*\* — for everything else, a Random Forest classifier analyzes how the traffic actually behaves. Even a brand new IP gives itself away through its traffic patterns.



\---



\## Results



Trained on \*\*2,827,876 network flows\*\* from the CICIDS2017 dataset:



| Metric | Value |

|--------|-------|

| Accuracy | \*\*99.80%\*\* |

| ROC-AUC | \*\*0.9999\*\* |

| False Negatives | \*\*159\*\* / 454,264 |

| False Positives | \*\*1,660\*\* / 454,264 |



Miss rate: \*\*0.035%\*\* — fewer than 4 attacks missed per 10,000.



\---



\## Features



\- 🔍 \*\*Single Flow Analysis\*\* — enter an IP and 25 flow features, get a full hybrid verdict with probability scores and feature attribution

\- 📂 \*\*Batch CSV Analysis\*\* — upload a file, process thousands of flows at once, download results

\- 📊 \*\*Model Insights\*\* — full feature importance ranking, detection pipeline diagram, model details

\- 🌐 \*\*Live Threat Feeds\*\* — Emerging Threats + Abuse.ch Feodo Tracker, cached and auto-refreshed every 6 hours

\- 💡 \*\*Explainable AI\*\* — every alert shows exactly which network features triggered it



\---



\## How It Works



```

Incoming Network Flow

&#x20;       ↓

\[Stage 1] Static IP Check → Known Malicious IP?

&#x20;       ↓ YES                      ↓ NO

&#x20;   🚨 BLOCK              \[Stage 2] Random Forest

&#x20;                         → Behavioral Analysis

&#x20;                                  ↓

&#x20;                      🚨 ATTACK       ✅ BENIGN

```



Stage 1 is fast. Stage 2 catches what Stage 1 can't.



\---



\## Quick Start



\### 1. Clone the repo



```bash

git clone https://github.com/AlaaZahra/ioc-sentinel.git

cd ioc-sentinel

```



\### 2. Install dependencies



```bash

pip install pandas numpy scikit-learn streamlit matplotlib joblib imbalanced-learn requests xgboost

```



\### 3. Get the dataset



Download CICIDS2017 from the \[Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) and place the CSV files in the `data/` folder.



\### 4. Prepare the data



```bash

python src/data\_prep.py

```



\### 5. Train the model



```bash

python src/train\_model.py

```



\### 6. Launch the dashboard



```bash

streamlit run src/dashboard.py

```



Open `http://localhost:8501` in your browser.



\---



\## Project Structure



```

ioc\_sentinel/

├── src/

│   ├── data\_prep.py        # Load and clean CICIDS2017

│   ├── train\_model.py      # Train Random Forest + save artifacts

│   ├── threat\_feeds.py     # Live threat intelligence integration

│   └── dashboard.py        # Streamlit dashboard

├── models/

│   ├── rf\_model.pkl        # Trained Random Forest

│   ├── scaler.pkl          # StandardScaler

│   └── feature\_names.pkl   # Feature list

├── data/                   # CICIDS2017 CSV files (not tracked)

└── README.md

```



\---



\## Dataset



\*\*CICIDS2017\*\* — Canadian Institute for Cybersecurity



| Class | Count | % |

|-------|-------|---|

| BENIGN | 2,271,320 | 80.3% |

| ATTACK | 556,556 | 19.7% |

| \*\*Total\*\* | \*\*2,827,876\*\* | |



After SMOTE balancing: \*\*4,542,640 samples\*\* (balanced 50/50).



Attack types covered: DoS, DDoS, Brute Force (FTP/SSH), Web Attacks (SQLi, XSS, Heartbleed), Botnet, Infiltration, Port Scanning.



\---



\## Model



\*\*Random Forest\*\* — 100 trees, max depth 20, class\_weight balanced



Top features by importance:



| Rank | Feature | Score |

|------|---------|-------|

| 1 | Destination Port | 0.1107 |

| 2 | Avg Bwd Segment Size | 0.1100 |

| 3 | Bwd Packet Length Min | 0.0843 |

| 4 | Init Win Bytes Backward | 0.0812 |

| 5 | Bwd Packet Length Max | 0.0759 |



Packet size asymmetry and TCP window configurations turn out to be the strongest behavioral signals for distinguishing attack traffic from normal communication.



\---



\## Threat Intelligence Sources



| Feed | Description | Refresh |

|------|-------------|---------|

| Static Blacklist | Curated known-bad IPs | Manual |

| Emerging Threats | Compromised IP blocklist | Every 6h |

| Abuse.ch Feodo | Botnet C2 infrastructure | Every 6h |



If external feeds are unreachable, the system falls back to the static list automatically.



\---



\## Tech Stack



| Component | Library |

|-----------|---------|

| ML Model | scikit-learn |

| Imbalance Handling | imbalanced-learn (SMOTE) |

| Dashboard | Streamlit |

| Model Persistence | joblib |

| Threat Feeds | requests |

| Data Processing | pandas, numpy |



\---



\## Academic Context



This project was developed as part of \*\*CISC 819 – Intelligent Cybersecurity Systems\*\* at Queen's University at Kingston, School of Computing.



\*\*Team:\*\* Alaa Zahra \& Maryam Abdalbary  

\*\*Instructor:\*\* Dr. Jianbing Ni



\*\*Reference:\*\* Sharafaldin, I., Lashkari, A. H., \& Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. \*ICISSP\*, 108–116.



\---



\## Future Work



\- Multi-class classification (distinguish DoS vs Brute Force vs Web attacks)

\- Live packet capture integration via CICFlowMeter

\- SHAP values for more granular per-prediction explanations

\- LSTM-based sequence models for temporal pattern detection

\- Automated alert escalation for production SOC integration



\---



<div align="center">



\*\*IOC Sentinel\*\* — Predictive Intelligence. Proactive Defense.



</div>

