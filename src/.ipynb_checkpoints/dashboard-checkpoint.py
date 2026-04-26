import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from threat_feeds import check_ip, get_feed_stats

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IOC Sentinel",
    page_icon="🛡️",
    layout="wide"
)

# ─── Load Artifacts ────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    model    = joblib.load("models/rf_model.pkl")
    scaler   = joblib.load("models/scaler.pkl")
    features = joblib.load("models/feature_names.pkl")
    return model, scaler, features

model, scaler, FEATURES = load_model()

# ─── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .alert-red   { color: #ff4b4b; font-size: 1.4rem; font-weight: bold; }
    .alert-green { color: #00c48c; font-size: 1.4rem; font-weight: bold; }
    .alert-orange{ color: #f39c12; font-size: 1.4rem; font-weight: bold; }
    .tag-red     { background:#ff4b4b; color:white; padding:3px 10px;
                   border-radius:5px; font-size:0.85rem; }
    .tag-green   { background:#00c48c; color:white; padding:3px 10px;
                   border-radius:5px; font-size:0.85rem; }
    .tag-orange  { background:#f39c12; color:white; padding:3px 10px;
                   border-radius:5px; font-size:0.85rem; }
</style>
""", unsafe_allow_html=True)

# ─── Header ────────────────────────────────────────────────────────────────────
st.markdown("# IOC Sentinel")
st.markdown("### Predictive Threat Intelligence & IOC Detection")
st.divider()

# ─── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/fluency/96/security-checked.png", width=80)
st.sidebar.title("IOC Sentinel")
st.sidebar.markdown("---")

mode = st.sidebar.radio(
    "Select Mode",
    [" Single Flow Analysis", " Batch File Analysis", " Model Insights"]
)

# Feed stats in sidebar
st.sidebar.markdown("---")
st.sidebar.markdown("###  Threat Feed Status")
try:
    stats = get_feed_stats()
    st.sidebar.success(f" Active")
    st.sidebar.markdown(f"**IPs in Blacklist:** {stats['total_ips']:,}")
    st.sidebar.markdown(f"**Last Update:** {stats['last_update']}")
    for src in stats['sources']:
        st.sidebar.markdown(f"- {src}")
except:
    st.sidebar.error(" Feeds not loaded yet")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 1 — Single Flow Analysis
# ══════════════════════════════════════════════════════════════════════════════
if mode == " Single Flow Analysis":
    st.subheader(" Analyze a Single Network Flow")
    st.info("Enter the source IP and network flow features for a full hybrid analysis.")

    # ── IP Check Section ──────────────────────────────────────────────────────
    st.markdown("#### Step 1 — Static IP Check")
    ip_input = st.text_input("Source IP Address", placeholder="e.g. 185.220.101.1")

    ip_result = None
    if ip_input:
        ip_result = check_ip(ip_input)
        c1, c2, c3 = st.columns(3)
        with c1:
            if ip_result["is_malicious"]:
                st.markdown('<p class="alert-red"> IP IS BLACKLISTED</p>',
                            unsafe_allow_html=True)
            else:
                st.markdown('<p class="alert-green"> IP NOT IN BLACKLIST</p>',
                            unsafe_allow_html=True)
        with c2:
            st.metric("Source", ip_result["source"])
        with c3:
            st.metric("Feed Size", f"{ip_result['feed_size']:,} IPs")

        if ip_result["is_malicious"]:
            st.error(" This IP is known malicious. No further analysis needed — BLOCK IT.")
            st.stop()

    st.divider()

    # ── Behavioral Analysis Section ───────────────────────────────────────────
    st.markdown("#### Step 2 — Behavioral AI Analysis (Random Forest)")
    st.caption("IP not in blacklist — analyzing traffic behavior...")

    col1, col2, col3 = st.columns(3)

    with col1:
        dst_port      = st.number_input("Destination Port",         0, 65535, 80)
        flow_duration = st.number_input("Flow Duration (μs)",       0, 10_000_000, 50000)
        fwd_packets   = st.number_input("Total Fwd Packets",        0, 10000, 10)
        bwd_packets   = st.number_input("Total Backward Packets",   0, 10000, 8)
        fwd_len_total = st.number_input("Total Length Fwd Packets", 0, 100000, 1500)
        bwd_len_total = st.number_input("Total Length Bwd Packets", 0, 100000, 1200)
        fwd_len_max   = st.number_input("Fwd Packet Length Max",    0, 65535, 500)
        fwd_len_min   = st.number_input("Fwd Packet Length Min",    0, 65535, 20)

    with col2:
        fwd_len_mean  = st.number_input("Fwd Packet Length Mean",   0.0, 65535.0, 150.0)
        bwd_len_max   = st.number_input("Bwd Packet Length Max",    0, 65535, 400)
        bwd_len_min   = st.number_input("Bwd Packet Length Min",    0, 65535, 20)
        flow_bytes_s  = st.number_input("Flow Bytes/s",             0.0, 1e9, 50000.0)
        flow_pkts_s   = st.number_input("Flow Packets/s",           0.0, 1e6, 200.0)
        flow_iat_mean = st.number_input("Flow IAT Mean",            0.0, 1e7, 5000.0)
        flow_iat_std  = st.number_input("Flow IAT Std",             0.0, 1e7, 3000.0)
        fwd_iat_total = st.number_input("Fwd IAT Total",            0.0, 1e8, 40000.0)

    with col3:
        bwd_iat_total = st.number_input("Bwd IAT Total",            0.0, 1e8, 30000.0)
        fwd_psh       = st.number_input("Fwd PSH Flags",            0, 10, 0)
        syn_flag      = st.number_input("SYN Flag Count",           0, 10, 1)
        rst_flag      = st.number_input("RST Flag Count",           0, 10, 0)
        ack_flag      = st.number_input("ACK Flag Count",           0, 100, 5)
        init_win_fwd  = st.number_input("Init Win Bytes Forward",   0, 65535, 8192)
        init_win_bwd  = st.number_input("Init Win Bytes Backward",  0, 65535, 8192)
        avg_fwd_seg   = st.number_input("Avg Fwd Segment Size",     0.0, 65535.0, 150.0)
        avg_bwd_seg   = st.number_input("Avg Bwd Segment Size",     0.0, 65535.0, 150.0)

    if st.button(" Run Full Analysis", use_container_width=True):
        input_values = [
            dst_port, flow_duration, fwd_packets, bwd_packets,
            fwd_len_total, bwd_len_total, fwd_len_max, fwd_len_min,
            fwd_len_mean, bwd_len_max, bwd_len_min, flow_bytes_s,
            flow_pkts_s, flow_iat_mean, flow_iat_std, fwd_iat_total,
            bwd_iat_total, fwd_psh, syn_flag, rst_flag, ack_flag,
            init_win_fwd, init_win_bwd, avg_fwd_seg, avg_bwd_seg
        ]

        input_df = pd.DataFrame([input_values], columns=FEATURES)
        scaled   = scaler.transform(input_df)
        pred     = model.predict(scaled)[0]
        prob     = model.predict_proba(scaled)[0]

        st.divider()
        st.markdown("####  Analysis Result")

        r1, r2, r3 = st.columns(3)

        with r1:
            # Combined verdict
            if pred == 1:
                st.markdown('<p class="alert-red"> ATTACK DETECTED</p>',
                            unsafe_allow_html=True)
                st.markdown('<span class="tag-red">Detected by: Behavioral AI</span>',
                            unsafe_allow_html=True)
                st.markdown(">  This IP was **not** in any blacklist but behaves like an attack.")
            else:
                st.markdown('<p class="alert-green"> BENIGN TRAFFIC</p>',
                            unsafe_allow_html=True)
                st.markdown('<span class="tag-green">Both checks passed</span>',
                            unsafe_allow_html=True)

        with r2:
            st.metric("Attack Probability", f"{prob[1]*100:.2f}%")
            st.metric("Benign Probability", f"{prob[0]*100:.2f}%")
            st.metric("Detection Stage",
                      "Behavioral AI" if ip_result and not ip_result["is_malicious"]
                      else "Static Feed")

        with r3:
            importances = model.feature_importances_
            top_idx     = np.argsort(importances)[::-1][:5]
            top_feats   = [FEATURES[i] for i in top_idx]
            top_vals    = [importances[i] for i in top_idx]

            fig, ax = plt.subplots(figsize=(4, 2.5))
            fig.patch.set_facecolor('#1e2130')
            ax.set_facecolor('#1e2130')
            ax.barh(top_feats[::-1], top_vals[::-1], color='#c0392b')
            ax.set_title("Top Triggering Features", color='white', fontsize=9)
            ax.tick_params(colors='white', labelsize=7)
            for spine in ax.spines.values():
                spine.set_visible(False)
            st.pyplot(fig)
            plt.close()

# ══════════════════════════════════════════════════════════════════════════════
# MODE 2 — Batch File Analysis
# ══════════════════════════════════════════════════════════════════════════════
elif mode == " Batch File Analysis":
    st.subheader(" Upload a CSV File for Batch Analysis")
    st.info("Upload a network flow CSV. If a 'src_ip' column exists, IPs will be checked against blacklists first.")

    uploaded = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        st.write(f"Loaded **{len(df):,}** rows")

        # ── IP Check if column exists ─────────────────────────────────────────
        blacklisted_count = 0
        if 'src_ip' in df.columns:
            st.markdown("#### Step 1 — Static IP Check")
            with st.spinner("Checking IPs against threat feeds..."):
                ip_results = df['src_ip'].apply(
                    lambda ip: check_ip(str(ip))["is_malicious"]
                )
                df['IP_Blacklisted'] = ip_results
                blacklisted_count = ip_results.sum()
            st.warning(f" {blacklisted_count:,} IPs found in blacklist — flagged immediately.")

        # ── Behavioral Analysis ───────────────────────────────────────────────
        st.markdown("#### Step 2 — Behavioral AI Analysis")

        missing = [f for f in FEATURES if f not in df.columns]
        if missing:
            st.warning(f"Missing features (will use 0): {missing}")
            for m in missing:
                df[m] = 0

        X      = df[FEATURES]
        scaled = scaler.transform(X)
        preds  = model.predict(scaled)
        probs  = model.predict_proba(scaled)[:, 1]

        df['ML_Prediction']  = np.where(preds == 1, ' ATTACK', ' BENIGN')
        df['Attack_Prob_%']  = (probs * 100).round(2)

        # Final verdict — blacklisted OR ML attack
        if 'IP_Blacklisted' in df.columns:
            df['Final_Verdict'] = np.where(
                df['IP_Blacklisted'] | (preds == 1),
                ' THREAT', ' SAFE'
            )
        else:
            df['Final_Verdict'] = df['ML_Prediction']

       # ── Metrics ───────────────────────────────────────────────────────────
        total_threats = int((df['Final_Verdict'].str.contains('THREAT', na=False)).sum())
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Flows",       f"{len(df):,}")
        m2.metric("Blacklisted IPs",   f"{blacklisted_count:,}")
        m3.metric("ML Attacks",        f"{(preds==1).sum():,}")
        m4.metric("Total Threats",     f"{total_threats:,}")
        m5.metric("Threat Rate", f"{float(total_threats)/len(df)*100:.1f}%")
        st.divider()

        # ── Bar Chart instead of Pie ──────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(4, 3))
        fig.patch.set_facecolor('#1e2130')
        ax.set_facecolor('#1e2130')
        safe_count   = (preds == 0).sum()
        attack_count = (preds == 1).sum()
        ax.bar(['BENIGN', 'ATTACK'], [safe_count, attack_count],
               color=['#00c48c', '#ff4b4b'])
        ax.set_title("Traffic Classification", color='white')
        ax.tick_params(colors='white')
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.yaxis.label.set_color('white')
        st.pyplot(fig)
        plt.close()

        st.divider()
        show_cols = ['Final_Verdict', 'ML_Prediction', 'Attack_Prob_%']
        if 'src_ip' in df.columns:
            show_cols = ['src_ip', 'IP_Blacklisted'] + show_cols
        st.dataframe(df[show_cols].head(200), use_container_width=True)

        csv_out = df.to_csv(index=False).encode('utf-8')
        st.download_button(" Download Results CSV",
                           csv_out, "ioc_sentinel_results.csv", "text/csv")

# ══════════════════════════════════════════════════════════════════════════════
# MODE 3 — Model Insights
# ══════════════════════════════════════════════════════════════════════════════
elif mode == " Model Insights":
    st.subheader(" Model Feature Importance")
    st.info("These are the network features the AI considers most important for detection.")

    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1]
    sorted_feat = [FEATURES[i] for i in indices]
    sorted_imp  = [importances[i] for i in indices]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#1e2130')
    ax.set_facecolor('#1e2130')
    colors = ['#c0392b' if i < 3 else '#e67e22' if i < 6 else '#3498db'
              for i in range(len(sorted_feat))]
    ax.barh(sorted_feat[::-1], sorted_imp[::-1], color=colors[::-1])
    ax.set_xlabel("Importance Score", color='white')
    ax.set_title("Feature Importance — Random Forest", color='white', fontsize=14)
    ax.tick_params(colors='white')
    for spine in ax.spines.values():
        spine.set_visible(False)
    st.pyplot(fig)
    plt.close()

    st.divider()

    # ── Detection Pipeline Diagram ────────────────────────────────────────────
    st.subheader(" Hybrid Detection Pipeline")
    st.markdown("""
    Incoming Network Flow
       ↓
[Stage 1] Static IP Check
→ Known Malicious IP?
       ↓ YES              ↓ NO
    BLOCK          [Stage 2] Random Forest
                     → Behavioral Analysis
                            ↓
                 ATTACK        BENIGN
                """)

    st.divider()
    st.subheader("Model Details")
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Algorithm",     "Random Forest")
    d2.metric("Trees",         "100")
    d3.metric("Features Used", str(len(FEATURES)))
    d4.metric("Training Data", "CICIDS2017")