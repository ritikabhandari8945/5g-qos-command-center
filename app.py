import streamlit as st
import time
import numpy as np
from collections import deque
from scapy.all import sniff
from scapy.layers.inet import TCP, UDP, ICMP
import pandas as pd
from datetime import datetime

# =========================
# 5G CORE & NSSF ENGINE
# =========================
class CoreNetwork:
    def __init__(self):
        self.ue_count = 50
        
    def get_metrics(self, attack_type=None):
        amf_base = 18 if attack_type == "Signaling Storm" else 3
        self.ue_count = max(5, self.ue_count + np.random.poisson(amf_base) - np.random.poisson(3))
        amf_load = min(100.0, (self.ue_count * 0.5) + np.random.uniform(0, 5))

        smf_lag = 40 if attack_type == "Session Exhaustion" else 0
        smf_load = min(100.0, (self.ue_count * 0.6) + smf_lag + np.random.uniform(0, 3))

        upf_spike = 45 if attack_type == "DDoS / Heavy Load" else 0
        upf_util = min(100.0, (self.ue_count * 0.8) + upf_spike + np.random.normal(0, 5))

        return {"AMF": amf_load, "SMF": smf_load, "UPF": upf_util, "UEs": self.ue_count}

def calculate_z_score(data_queue):
    if len(data_queue) < 15: return 0.0
    data = np.array(data_queue)
    mean, std = np.mean(data[:-1]), np.std(data[:-1])
    return abs(data[-1] - mean) / std if std > 1e-6 else 0.0

# =========================
# STREAMLIT CONFIG & STYLE
# =========================
st.set_page_config(page_title="5G QoS Command Center", layout="wide")

st.markdown("""
<style>
    .stApp { background: radial-gradient(circle at bottom left, #0d1b2a, #010409); color: #e6edf3; }
    .glass-card {
        background: rgba(255, 255, 255, 0.03); border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.1); padding: 1.2rem;
        backdrop-filter: blur(12px); margin-bottom: 1rem;
    }
    .metric-container { text-align: center; }
    .metric-value { font-size: 1.8rem; font-weight: 800; margin: 2px 0; }
    .metric-label { font-size: 0.7rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1.2px; }
    .slice-bar { height: 8px; border-radius: 4px; margin-bottom: 12px; background: rgba(255,255,255,0.1); overflow: hidden; }
    .slice-fill { height: 100%; transition: width 0.5s ease; }
</style>
""", unsafe_allow_html=True)

# =========================
# SESSION STATE INIT
# =========================
WINDOW_SIZE = 60
if "init" not in st.session_state:
    st.session_state.delays = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
    st.session_state.jitters = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
    st.session_state.throughputs = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)

    st.session_state.core_hist = {"AMF": deque(maxlen=WINDOW_SIZE), "SMF": deque(maxlen=WINDOW_SIZE), "UPF": deque(maxlen=WINDOW_SIZE)}
    st.session_state.logs = []
    st.session_state.packet_count = 0
    st.session_state.running = False
    st.session_state.attack_mode = None
    st.session_state.core = CoreNetwork()

    st.session_state.protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "GTP-U": 0,   # ✅ added
        "Other": 0
    }

    st.session_state.init = True

# =========================
# HELPERS
# =========================
def styled_metric(label, value, z_val=0, is_anom=False, suffix=""):
    color = "#ff4b4b" if is_anom else "#00d4ff"
    z_info = f"<div style='font-size:0.6rem; color:#8b949e;'>Dev: {z_val:.2f}σ</div>" if z_val > 0 else ""
    return f"""
    <div class="glass-card" style="border-bottom: 2px solid {color};">
        <div class="metric-container">
            <div class="metric-label">{label}</div>
            <div class="metric-value" style="color: {color};">{value}{suffix}</div>
            {z_info}
        </div>
    </div>
    """

def handle_packet(pkt):
    now = time.time()
    st.session_state.packet_count += 1

    if hasattr(st.session_state, 'prev_time') and st.session_state.prev_time:
        d = (now - st.session_state.prev_time) * 1000
        st.session_state.delays.append(d)
        st.session_state.jitters.append(abs(d - (st.session_state.prev_delay if hasattr(st.session_state, 'prev_delay') else d)))
        st.session_state.prev_delay = d

    st.session_state.prev_time = now
    st.session_state.throughputs.append(len(pkt) * 8 / 1024)

    if pkt.haslayer(TCP):
        st.session_state.protocol_counts["TCP"] += 1

    elif pkt.haslayer(UDP):
        st.session_state.protocol_counts["UDP"] += 1

        # ✅ GTP-U detection (UDP port 2152)
        if pkt[UDP].sport == 2152 or pkt[UDP].dport == 2152:
            st.session_state.protocol_counts["GTP-U"] += 1

    elif pkt.haslayer(ICMP):
        st.session_state.protocol_counts["ICMP"] += 1
    else:
        st.session_state.protocol_counts["Other"] += 1

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.header("📡 5G CORE OPS")
    if st.button("▶ START MONITORING", use_container_width=True, type="primary"):
        st.session_state.running = True
        st.session_state.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "GTP-U": 0, "Other": 0}

    if st.button("⏹ STOP ENGINE", use_container_width=True):
        st.session_state.running = False

    st.divider()
    st.subheader("Simulate Failures")
    if st.button("🚨 AMF STORM"): st.session_state.attack_mode = "Signaling Storm"
    if st.button("🚨 UPF DDoS"): st.session_state.attack_mode = "DDoS / Heavy Load"
    if st.button("✅ SYSTEM RECOVERY"): st.session_state.attack_mode = None
    st.divider()
    st.info("**Slicing:** NSSF Active\n**Analytics:** NWDAF Z-Score")

# =========================
# MAIN DASHBOARD
# =========================
st.title("5G QoS & Multi-Plane Anomaly Center")

if st.session_state.running:
    sniff(count=5, prn=handle_packet, store=False, timeout=0.05)
    m = st.session_state.core.get_metrics(st.session_state.attack_mode)
    
    results = {}
    for p in ["AMF", "SMF", "UPF"]:
        st.session_state.core_hist[p].append(m[p])
        z = calculate_z_score(st.session_state.core_hist[p])
        is_anom = z > 2.5
        results[p] = {"val": m[p], "z": z, "anom": is_anom}
        if is_anom:
            st.session_state.logs.append({"Time": datetime.now().strftime("%H:%M:%S"), "Plane": p, "Dev": f"{z:.1f}σ"})

    st.subheader("🏗️ 5G Core Network Functions")
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(styled_metric("AMF (Control)", f"{m['AMF']:.1f}", results['AMF']['z'], results['AMF']['anom'], "%"), unsafe_allow_html=True)
    c2.markdown(styled_metric("SMF (Session)", f"{m['SMF']:.1f}", results['SMF']['z'], results['SMF']['anom'], "%"), unsafe_allow_html=True)
    c3.markdown(styled_metric("UPF (Data)", f"{m['UPF']:.1f}", results['UPF']['z'], results['UPF']['anom'], "%"), unsafe_allow_html=True)
    c4.markdown(styled_metric("Active UEs", m['UEs']), unsafe_allow_html=True)

    st.markdown("---")
    col_qos, col_slice = st.columns([2, 1])
    
    with col_qos:
        st.subheader("🚀 User Experience (QoS)")
        q1, q2, q3 = st.columns(3)
        l_val = st.session_state.delays[-1] if st.session_state.delays else 0
        j_val = st.session_state.jitters[-1] if st.session_state.jitters else 0
        t_val = st.session_state.throughputs[-1] if st.session_state.throughputs else 0
        q1.markdown(styled_metric("Latency", f"{l_val:.2f}", 0, l_val > 80, "ms"), unsafe_allow_html=True)
        q2.markdown(styled_metric("Jitter", f"{j_val:.2f}", 0, j_val > 15, "ms"), unsafe_allow_html=True)
        q3.markdown(styled_metric("Throughput", f"{t_val:.1f}", 0, False, "Kbps"), unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📡 Protocol Distribution")
    st.markdown(f"**Total Captured Packets:** {st.session_state.packet_count}")

    protocols = st.session_state.protocol_counts
    max_val = max(protocols.values()) if max(protocols.values()) > 0 else 1

    for proto, count in protocols.items():
        bar_length = int((count / max_val) * 20)
        bar = "█" * bar_length
        space = " " * (20 - bar_length)

        st.markdown(f"""
        <div style="font-family: monospace; font-size:16px;">
        {proto:<5} {bar}{space} {count}
        </div>
        """, unsafe_allow_html=True)

    with col_slice:
        st.subheader("🍰 NSSF Traffic Slicing")
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        urllc = max(10, 95 - (m['AMF']*0.5))
        embb = min(90, m['UPF'] * 0.9)
        st.caption(f"URLLC Health: {urllc:.0f}%")
        st.markdown(f'<div class="slice-bar"><div class="slice-fill" style="width:{urllc}%; background:#00ffcc;"></div></div>', unsafe_allow_html=True)
        st.caption(f"eMBB Resource: {embb:.0f}%")
        st.markdown(f'<div class="slice-bar"><div class="slice-fill" style="width:{embb}%; background:#ffaa00;"></div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.divider()
    g_core, g_qos = st.columns(2)
    
    with g_core:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("📊 5G Core Plane Performance")
        core_df = pd.DataFrame({p: list(st.session_state.core_hist[p]) for p in ["AMF", "SMF", "UPF"]})
        st.line_chart(core_df, height=200)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with g_qos:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("📊 Real-Time QoS Trends")
        qos_df = pd.DataFrame({
            "Latency (ms)": list(st.session_state.delays),
            "Throughput (Kbps)": list(st.session_state.throughputs)
        })
        st.area_chart(qos_df, height=200)
        st.markdown('</div>', unsafe_allow_html=True)

    st.subheader("📑 Event Intelligence")
    if st.session_state.logs:
        st.dataframe(pd.DataFrame(st.session_state.logs).tail(10), use_container_width=True, hide_index=True)
    else:
        st.info("Continuous Baseline Monitoring: No Deviations Detected")

    time.sleep(0.1)
    st.rerun()

else:
    st.warning("Dashboard Idle. Start Monitoring to engage 5G NFs.")
