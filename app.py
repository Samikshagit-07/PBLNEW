# app.py

import streamlit as st
import pandas as pd
import time
import os
import sys
import platform
from datetime import datetime

# Ensure the root directory is in python path for absolute imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import backend modules
from modules.password_checker import check_password_strength
from modules.keylogger_detector import scan_for_keyloggers
from modules.network_analyzer import analyze_connections, get_traffic_stats, format_bytes

# Set Page Config
st.set_page_config(
    page_title="CyberShield: Cybersecurity Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyberpunk / Hacker theme
st.markdown("""
<style>
/* Import cyberpunk fonts */
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&family=Inter:wght@400;600&display=swap');

/* Main page layout overrides */
.stApp {
    background-color: #080B11;
    color: #E2E8F0;
    font-family: 'Inter', sans-serif;
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background-color: #0B0F19 !important;
    border-right: 2px solid #00F0FF;
}

/* Titles and neon texts */
.neon-title {
    font-family: 'Orbitron', sans-serif;
    color: #00F0FF;
    text-shadow: 0 0 10px rgba(0, 240, 255, 0.7);
    font-weight: 700;
    margin-bottom: 20px;
}
.neon-sub-title {
    font-family: 'Orbitron', sans-serif;
    color: #E2E8F0;
    font-weight: 600;
    margin-top: 15px;
    margin-bottom: 10px;
}
.neon-green {
    color: #00FF66 !important;
    text-shadow: 0 0 8px rgba(0, 255, 102, 0.4);
    font-family: 'Share Tech Mono', monospace;
}
.neon-cyan {
    color: #00F0FF !important;
    text-shadow: 0 0 8px rgba(0, 240, 255, 0.4);
    font-family: 'Share Tech Mono', monospace;
}
.neon-red {
    color: #FF3B30 !important;
    text-shadow: 0 0 8px rgba(255, 59, 48, 0.4);
    font-family: 'Share Tech Mono', monospace;
}
.neon-yellow {
    color: #FFD700 !important;
    text-shadow: 0 0 8px rgba(255, 215, 0, 0.4);
    font-family: 'Share Tech Mono', monospace;
}

/* Custom cyber cards */
.cyber-card {
    background-color: #111827;
    border: 1px solid #1F2937;
    border-radius: 8px;
    padding: 1.2rem;
    margin-bottom: 1rem;
    transition: all 0.3s ease;
}
.cyber-card:hover {
    border-color: #00F0FF;
    box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
}

.cyber-card-threat {
    background-color: #1A0D0E;
    border: 1px solid #7F1D1D;
    border-radius: 8px;
    padding: 1.2rem;
    margin-bottom: 1rem;
}
.cyber-card-threat:hover {
    border-color: #FF3B30;
    box-shadow: 0 0 10px rgba(255, 59, 48, 0.2);
}

.cyber-card-safe {
    background-color: #0B1912;
    border: 1px solid #064E3B;
    border-radius: 8px;
    padding: 1.2rem;
    margin-bottom: 1rem;
}
.cyber-card-safe:hover {
    border-color: #00FF66;
    box-shadow: 0 0 10px rgba(0, 255, 102, 0.2);
}

.cyber-card-warning {
    background-color: #1C1A10;
    border: 1px solid #78350F;
    border-radius: 8px;
    padding: 1.2rem;
    margin-bottom: 1rem;
}
.cyber-card-warning:hover {
    border-color: #FFD700;
    box-shadow: 0 0 10px rgba(255, 215, 0, 0.2);
}

/* Terminal emulator style */
.terminal-window {
    background-color: #05070A;
    border: 1px solid #00FF66;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Share Tech Mono', monospace;
    color: #33FF33;
    overflow-y: auto;
    max-height: 250px;
    box-shadow: inset 0 0 10px rgba(0, 255, 0, 0.1);
    white-space: pre-wrap;
    word-break: break-all;
}

/* Metrics styles */
.metric-container {
    background-color: #111827;
    border: 1px solid #1F2937;
    border-radius: 6px;
    padding: 10px 15px;
    text-align: center;
}
.metric-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #9CA3AF;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}
.metric-value-cyber {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.5rem;
    font-weight: bold;
    color: #00F0FF;
}

/* TLP indicators */
.tlp-dot {
    height: 12px;
    width: 12px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 8px;
}
.tlp-red {
    background-color: #FF3B30;
    box-shadow: 0 0 8px #FF3B30;
}
.tlp-yellow {
    background-color: #FFD700;
    box-shadow: 0 0 8px #FFD700;
}
.tlp-green {
    background-color: #00FF66;
    box-shadow: 0 0 8px #00FF66;
}
.tlp-grey {
    background-color: #6B7280;
    box-shadow: 0 0 4px #6B7280;
}
</style>
""", unsafe_allow_html=True)

# Initialize Session State Variables to persist scans across navigation tabs
if 'password_checked' not in st.session_state:
    st.session_state.password_checked = False
if 'password_results' not in st.session_state:
    st.session_state.password_results = None

if 'keylogger_scanned' not in st.session_state:
    st.session_state.keylogger_scanned = False
if 'keylogger_results' not in st.session_state:
    st.session_state.keylogger_results = None

if 'network_analyzed' not in st.session_state:
    st.session_state.network_analyzed = False
if 'network_results' not in st.session_state:
    st.session_state.network_results = None

if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = []
if 'live_monitoring' not in st.session_state:
    st.session_state.live_monitoring = False

# Threshold settings
if 'packet_threshold' not in st.session_state:
    st.session_state.packet_threshold = 1000
if 'byte_threshold_mb' not in st.session_state:
    st.session_state.byte_threshold_mb = 10

# Sidebar Navigation Layout
with st.sidebar:
    st.markdown('<h1 class="neon-title">🛡️ CyberShield</h1>', unsafe_allow_html=True)
    st.markdown('<p class="neon-cyan" style="font-size:0.8rem; margin-top:-10px;">Security Command Center</p>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Navigation options
    page = st.radio(
        "Select Operations Layer:",
        [
            "🖥️ Security Overview",
            "🔐 Password Analyzer",
            "🔍 Keylogger Scan",
            "🌐 Network Analyzer"
        ]
    )
    
    st.markdown("---")
    
    # System summary in sidebar
    st.markdown('<p class="neon-cyan" style="font-weight:bold; margin-bottom:5px;">SYSTEM TELEMETRY</p>', unsafe_allow_html=True)
    st.text(f"OS: {platform.system()} {platform.release()}")
    st.text(f"Platform: {platform.node()}")
    st.text(f"Core Count: {os.cpu_count()}")
    st.text(f"RAM: {round(platform.sys.api_version / (10**9), 2)} GB" if hasattr(platform.sys, 'api_version') else "Active")
    
    st.markdown("---")
    st.markdown('<p style="font-size: 0.7rem; color: #4B5563;">CyberShield Security Analyzer v1.0.0<br>© 2026 PBL Security Inc.</p>', unsafe_allow_html=True)

# ----------------- PAGE 1: Security Overview (Dashboard) -----------------
if page == "🖥️ Security Overview":
    st.markdown('<h1 class="neon-title">SECURITY COMMAND CENTER</h1>', unsafe_allow_html=True)
    st.markdown("### System Security Dashboard & Global Health Monitor")
    st.write("Welcome to the central command hub. Monitor the real-time status of your system's critical security layers below.")
    
    st.markdown("---")
    
    # Global Health Indicator calculation
    # We aggregate states from the 3 modules: Password, Keylogger, Network.
    # Scores (out of 100):
    # - Password Checker: 30 pts (based on strength: Very Strong=30, Strong=25, Moderate=20, Weak=10, Very Weak=0, Not Checked=15)
    # - Keylogger Scanner: 35 pts (No threat=35, Low=25, Medium=15, High=5, Critical=0, Not Scanned=20)
    # - Network Traffic: 35 pts (Safe=35, Low=25, Medium=15, High=5, Critical=0, Not Analyzed=20)
    
    pwd_pts = 15
    pwd_status_txt = "Not checked yet"
    pwd_tlp = "tlp-grey"
    if st.session_state.password_checked and st.session_state.password_results:
        strength = st.session_state.password_results['strength']
        pwd_status_txt = f"Password analyzed: {strength}"
        if strength in ("STRONG", "VERY STRONG"):
            pwd_pts = 30
            pwd_tlp = "tlp-green"
        elif strength == "MODERATE":
            pwd_pts = 20
            pwd_tlp = "tlp-yellow"
        else:
            pwd_pts = 5
            pwd_tlp = "tlp-red"
            
    key_pts = 20
    key_status_txt = "Scanner inactive"
    key_tlp = "tlp-grey"
    if st.session_state.keylogger_scanned and st.session_state.keylogger_results:
        risk = st.session_state.keylogger_results['risk_level']
        threats = st.session_state.keylogger_results['threat_count']
        key_status_txt = f"Scan complete. Risk: {risk} ({threats} threat(s))"
        if risk == "SAFE":
            key_pts = 35
            key_tlp = "tlp-green"
        elif risk in ("LOW", "MEDIUM"):
            key_pts = 20
            key_tlp = "tlp-yellow"
        else:
            key_pts = 0
            key_tlp = "tlp-red"
            
    net_pts = 20
    net_status_txt = "Network not checked"
    net_tlp = "tlp-grey"
    if st.session_state.network_analyzed and st.session_state.network_results:
        risk = st.session_state.network_results['risk_level']
        net_status_txt = f"Network analyzed. Risk: {risk}"
        if risk == "SAFE":
            net_pts = 35
            net_tlp = "tlp-green"
        elif risk in ("LOW", "MEDIUM"):
            net_pts = 20
            net_tlp = "tlp-yellow"
        else:
            net_pts = 0
            net_tlp = "tlp-red"
            
    global_score = pwd_pts + key_pts + net_pts
    
    # Determine overall status card and colors based on score
    if global_score >= 85:
        score_class = "neon-green"
        card_class = "cyber-card-safe"
        verdict = "SYSTEM STATUS: SECURE"
        desc = "All scanned systems are running optimally. No critical indicators of compromise have been flagged."
    elif global_score >= 60:
        score_class = "neon-yellow"
        card_class = "cyber-card-warning"
        verdict = "SYSTEM STATUS: WARNING"
        desc = "Minor vulnerabilities or warnings detected. We recommend strengthening passwords and investigating any network activity."
    else:
        score_class = "neon-red"
        card_class = "cyber-card-threat"
        verdict = "SYSTEM STATUS: COMPROMISED / VULNERABLE"
        desc = "Suspicious process threats, active vulnerabilities, or network anomalies detected. Take immediate remedial action."
        
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown(f"""
        <div class="{card_class}">
            <h2 class="{score_class}" style="margin-top:0;">{verdict}</h2>
            <p style="font-size:1.1rem; color:#9CA3AF; line-height:1.5;">{desc}</p>
            <div style="margin-top:20px;">
                <span class="tlp-dot {pwd_tlp}"></span><strong>Layer 1 (Identity):</strong> {pwd_status_txt}<br/>
                <span class="tlp-dot {key_tlp}"></span><strong>Layer 2 (Keylogger):</strong> {key_status_txt}<br/>
                <span class="tlp-dot {net_tlp}"></span><strong>Layer 3 (Network):</strong> {net_status_txt}
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
        <div class="cyber-card" style="text-align:center; height:100%; display: flex; flex-direction: column; justify-content: center;">
            <p class="metric-label" style="font-size:1rem;">Overall Integrity Score</p>
            <p class="metric-value-cyber {score_class}" style="font-size:4rem; margin:10px 0;">{global_score}%</p>
            <p style="font-size:0.8rem; color:#6B7280;">Aggregated health calculation based on active defense shields.</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown('<h2 class="neon-sub-title">CORE SECURITY CONTROLS</h2>', unsafe_allow_html=True)
    
    l1, l2, l3 = st.columns(3)
    
    with l1:
        st.markdown(f"""
        <div class="cyber-card">
            <h4 class="neon-cyan" style="margin-top:0;">🔐 PASSWORD ANALYZER</h4>
            <p style="font-size:0.85rem; color:#9CA3AF; min-height:60px;">Evaluates credential strength, checks common password listings, and catches sequence repetitions.</p>
            <div style="display:flex; align-items:center; justify-content:space-between; margin-top:15px;">
                <span style="font-size:0.85rem;">Status:</span>
                <span class="neon-green" style="font-size:0.95rem;"><span class="tlp-dot {pwd_tlp}"></span>Active</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with l2:
        st.markdown(f"""
        <div class="cyber-card">
            <h4 class="neon-cyan" style="margin-top:0;">🔍 KEYLOGGER PROCESS SCANNER</h4>
            <p style="font-size:0.85rem; color:#9CA3AF; min-height:60px;">Iterates through system processes to locate known spyware signatures, suspicious names, and Temp-path executions.</p>
            <div style="display:flex; align-items:center; justify-content:space-between; margin-top:15px;">
                <span style="font-size:0.85rem;">Status:</span>
                <span class="neon-green" style="font-size:0.95rem;"><span class="tlp-dot {key_tlp}"></span>Active</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with l3:
        st.markdown(f"""
        <div class="cyber-card">
            <h4 class="neon-cyan" style="margin-top:0;">🌐 NETWORK TRAFFIC ANALYZER</h4>
            <p style="font-size:0.85rem; color:#9CA3AF; min-height:60px;">Scans connections for suspect ports, maps unknown endpoints, monitors traffic rates, and checks for DDoS patterns.</p>
            <div style="display:flex; align-items:center; justify-content:space-between; margin-top:15px;">
                <span style="font-size:0.85rem;">Status:</span>
                <span class="neon-green" style="font-size:0.95rem;"><span class="tlp-dot {net_tlp}"></span>Active</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ----------------- PAGE 2: Password Checker -----------------
elif page == "🔐 Password Analyzer":
    st.markdown('<h1 class="neon-title">PASSWORD STRENGTH CHECKER</h1>', unsafe_allow_html=True)
    st.markdown("### Layer 1: Access Controls & Identity Protection")
    st.write("Ensure your access credentials can withstand brute-force attacks. This analyzer evaluates length, entropy, and rulesets locally.")
    
    st.markdown("---")
    
    col1, col2 = st.columns([1, 1.2])
    
    with col1:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown('<h4 class="neon-cyan" style="margin-top:0; margin-bottom:15px;">Input Security Credential</h4>', unsafe_allow_html=True)
        
        # Masked text input
        password_input = st.text_input(
            "Enter password to evaluate:",
            type="password",
            help="Your password is analyzed entirely locally in memory. It is never transmitted over the network."
        )
        
        analyze_btn = st.button("Execute Strength Test", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        if analyze_btn or (password_input and not st.session_state.password_checked):
            if not password_input:
                st.warning("⚠️ Please provide a non-empty password to check.")
            else:
                st.session_state.password_results = check_password_strength(password_input)
                st.session_state.password_checked = True
                st.rerun()

    with col2:
        if st.session_state.password_checked and st.session_state.password_results:
            res = st.session_state.password_results
            
            # Select color based on strength
            lvl = res['strength_level'] # 1 to 5
            strength_str = res['strength']
            score = res['score']
            max_score = res['max_score']
            
            if lvl <= 2:
                strength_color = "neon-red"
                alert_box = "cyber-card-threat"
                icon = "🚨"
            elif lvl == 3:
                strength_color = "neon-yellow"
                alert_box = "cyber-card-warning"
                icon = "⚠️"
            else:
                strength_color = "neon-green"
                alert_box = "cyber-card-safe"
                icon = "✅"
                
            # Strength indicator characters
            bar_filled = "█" * lvl
            bar_empty = "░" * (5 - lvl)
            
            st.markdown(f"""
            <div class="{alert_box}">
                <h3 class="{strength_color}" style="margin-top:0;">{icon} VERDICT: {strength_str}</h3>
                <hr style="border-color:#555; margin:10px 0;"/>
                <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                    <span>Raw Strength Rating:</span>
                    <span class="{strength_color}" style="font-weight:bold;">{score} / {max_score}</span>
                </div>
                <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-family:'Share Tech Mono', monospace;">
                    <span>Security Gauge:</span>
                    <span class="{strength_color}" style="font-weight:bold; letter-spacing:3px;">[{bar_filled}{bar_empty}]</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Displays what is good and issues
            st.markdown('<h4 class="neon-cyan">ANALYSIS BREAKDOWN</h4>', unsafe_allow_html=True)
            
            good_col, bad_col = st.columns(2)
            
            with good_col:
                st.write("##### ✅ What's Good:")
                if res['feedback']:
                    for fb in res['feedback']:
                        st.markdown(f"- <span style='color:#00FF66;'>{fb}</span>", unsafe_allow_html=True)
                else:
                    st.write("*No passing rules identified.*")
                    
            with bad_col:
                st.write("##### ❌ Issues Found:")
                if res['issues']:
                    for issue in res['issues']:
                        st.markdown(f"- <span style='color:#FF3B30;'>{issue}</span>", unsafe_allow_html=True)
                else:
                    st.write("*No vulnerabilities flagged! Excellent work.*")
        else:
            st.info("💡 Input a password and select 'Execute Strength Test' to review analytics.")


# ----------------- PAGE 3: Keylogger Detector -----------------
elif page == "🔍 Keylogger Scan":
    st.markdown('<h1 class="neon-title">PROCESS & KEYLOGGER THREAT SCANNER</h1>', unsafe_allow_html=True)
    st.markdown("### Layer 2: Spyware and Keystroke Capture Protection")
    st.write("Scans running processes against heuristics and databases for signatures representing remote access trojans (RATs) and keyloggers.")
    
    st.markdown("---")
    
    # Controls layout
    c1, c2 = st.columns([1, 1])
    
    with c1:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown('<h4 class="neon-cyan" style="margin-top:0;">Scan Configuration</h4>', unsafe_allow_html=True)
        st.write("Initiate a process scan. This scanner checks the executable paths, keywords, and known malware hashes to locate potential spyware.")
        
        # Trigger button
        scan_btn = st.button("RUN DEEP SECURITY SCAN", type="primary", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with c2:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown('<h4 class="neon-cyan" style="margin-top:0;">Scanning Engine Info</h4>', unsafe_allow_html=True)
        st.write("Scanning rules include checks for running in `temp` directories, known RAT names (`darkcomet`, `remcos`, `njrat`), and suspicious keyboards hook words.")
        st.markdown('</div>', unsafe_allow_html=True)
        
    # Scanning logic
    if scan_btn:
        progress_bar = st.progress(0)
        status_box = st.empty()
        
        def progress_callback(scanned, total, proc_name):
            pct = min(1.0, float(scanned) / float(total))
            progress_bar.progress(pct)
            status_box.code(f"Scanning PID: [{scanned}/{total}] -> Checking: {proc_name[:40]}...")
            time.sleep(0.003) # brief animation pause
            
        with st.spinner("Analyzing system processes against threat intelligence..."):
            results = scan_for_keyloggers(verbose=False, progress_callback=progress_callback)
            st.session_state.keylogger_results = results
            st.session_state.keylogger_scanned = True
            
        # Clean progress markers
        progress_bar.empty()
        status_box.empty()
        st.rerun()

    # Results view
    if st.session_state.keylogger_scanned and st.session_state.keylogger_results:
        res = st.session_state.keylogger_results
        threat_cnt = res['threat_count']
        scanned_cnt = res['total_scanned']
        risk_lvl = res['risk_level']
        scan_time = res['scan_time']
        
        if threat_cnt > 0:
            status_class = "neon-red"
            card_class = "cyber-card-threat"
            verdict_text = f"WARNING: {threat_cnt} Suspicious Process(es) Flagged!"
            icon = "🚨"
        else:
            status_class = "neon-green"
            card_class = "cyber-card-safe"
            verdict_text = "System Scan Completed Successfully: SAFE"
            icon = "✅"
            
        st.markdown(f"""
        <div class="{card_class}">
            <h3 class="{status_class}" style="margin-top:0;">{icon} {verdict_text}</h3>
            <p style="margin-bottom:0;">System scan executed at: <b>{scan_time}</b> | Analyzed <b>{scanned_cnt}</b> processes | System Risk Rating: <b class="{status_class}">{risk_lvl}</b></p>
        </div>
        """, unsafe_allow_html=True)
        
        if threat_cnt > 0:
            st.markdown('<h3 class="neon-sub-title">SUSPICIOUS THREAT LOGS</h3>', unsafe_allow_html=True)
            
            # Build DataFrame
            threat_list = []
            for t in res['threats_found']:
                threat_list.append({
                    "PID": t["pid"],
                    "Process Name": t["name"],
                    "Risk Score": t["risk_score"],
                    "Location": t["exe"],
                    "User": t["username"],
                    "Created": t["created"],
                    "Triggers": ", ".join(t["reasons"])
                })
            df = pd.DataFrame(threat_list)
            
            # Displays details in streamlit table
            st.dataframe(df, use_container_width=True)
            
            # Terminal Style logging for security analysts
            st.markdown('<h4 class="neon-cyan">RAW SCANNER SECURITY TELEMETRY</h4>', unsafe_allow_html=True)
            
            log_output = f"--- CyberShield Security Dump: {scan_time} ---\n"
            log_output += f"Total Process Scanned: {scanned_cnt}\n"
            log_output += f"Total Alerts Found   : {threat_cnt}\n"
            log_output += f"Aggregated Threat Profile: {risk_lvl}\n"
            log_output += "========================================\n\n"
            
            for i, t in enumerate(res['threats_found'], 1):
                log_output += f"[THREAT #{i}] Name: {t['name']} (PID: {t['pid']})\n"
                log_output += f"  - Location  : {t['exe']}\n"
                log_output += f"  - Command   : {t['cmdline']}\n"
                log_output += f"  - Status    : {t['status']}\n"
                log_output += f"  - Risk Score: {t['risk_score']}/5\n"
                log_output += f"  - Flagged Triggers:\n"
                for reason in t['reasons']:
                    log_output += f"     * {reason}\n"
                log_output += "\n"
                
            st.markdown(f'<div class="terminal-window">{log_output}</div>', unsafe_allow_html=True)
        else:
            st.success("🎉 No suspicious processes or malicious keystroke hooks matching threats were detected during scanning.")
    else:
        st.info("💡 Click the 'RUN DEEP SECURITY SCAN' button to inspect processes running on your OS.")


# ----------------- PAGE 4: Network Traffic Analyzer -----------------
elif page == "🌐 Network Analyzer":
    st.markdown('<h1 class="neon-title">NETWORK TRAFFIC & CONNECTION ANALYZER</h1>', unsafe_allow_html=True)
    st.markdown("### Layer 3: Boundary Protection & Traffic Metrics")
    st.write("Analyze live connections, filter endpoints, and detect patterns representing denial-of-service (DDoS) or network scans.")
    
    st.markdown("---")
    
    col1, col2 = st.columns([1.1, 2])
    
    with col1:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown('<h4 class="neon-cyan" style="margin-top:0;">Security Threshold Settings</h4>', unsafe_allow_html=True)
        st.write("Adjust rate thresholds to catch anomalous traffic volumes and possible denial of service triggers:")
        
        # Interactive Threshold sliders
        pkt_threshold = st.slider(
            "DDoS Packet Rate Limit (packets/sec)",
            min_value=100,
            max_value=5000,
            value=st.session_state.packet_threshold,
            step=100,
            key="slider_pkt_threshold"
        )
        st.session_state.packet_threshold = pkt_threshold
        
        byte_threshold_mb = st.slider(
            "DDoS Bandwidth Rate Limit (MB/s)",
            min_value=1,
            max_value=100,
            value=st.session_state.byte_threshold_mb,
            step=1,
            key="slider_byte_threshold"
        )
        st.session_state.byte_threshold_mb = byte_threshold_mb
        
        st.markdown("---")
        
        # Run scan button
        scan_conn = st.button("RUN CONNECTION PROFILE SCAN", use_container_width=True, type="primary")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
    with col2:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown('<h4 class="neon-cyan" style="margin-top:0;">Live Port & Endpoints Monitor</h4>', unsafe_allow_html=True)
        st.write("Toggle live network metrics capturing to plot a real-time data array chart of bandwidth upload/download speeds:")
        
        live_btn_lbl = "STOP LIVE TRAFFIC MONITOR" if st.session_state.live_monitoring else "START LIVE TRAFFIC MONITOR"
        
        if st.button(live_btn_lbl, use_container_width=True):
            st.session_state.live_monitoring = not st.session_state.live_monitoring
            if st.session_state.live_monitoring:
                # Clear past charts
                st.session_state.traffic_history = []
            st.rerun()
            
        st.markdown("</div>", unsafe_allow_html=True)
        
    # Running connections profile scan
    if scan_conn:
        with st.spinner("Analyzing active sockets and resolving hostname domains..."):
            results = analyze_connections(
                packet_threshold=st.session_state.packet_threshold,
                byte_threshold_mb=st.session_state.byte_threshold_mb
            )
            st.session_state.network_results = results
            st.session_state.network_analyzed = True
            
        # Append latest sample to history if live monitoring isn't running
        t_stats = results["traffic"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        st.session_state.traffic_history.append({
            "Time": timestamp,
            "Inbound (MB/s)": round(t_stats["bytes_recv_ps"] / (1024**2), 3),
            "Outbound (MB/s)": round(t_stats["bytes_sent_ps"] / (1024**2), 3)
        })
        if len(st.session_state.traffic_history) > 30:
            st.session_state.traffic_history.pop(0)
            
        st.rerun()
        
    # LIVE MONITOR LOOP (if toggled active)
    if st.session_state.live_monitoring:
        placeholder = st.empty()
        
        # We run the loop while live monitoring is toggled
        while st.session_state.live_monitoring:
            t_stats = get_traffic_stats() # blocks for 1 second inside module
            timestamp = datetime.now().strftime("%H:%M:%S")
            in_mb = round(t_stats["bytes_recv_ps"] / (1024**2), 3)
            out_mb = round(t_stats["bytes_sent_ps"] / (1024**2), 3)
            
            st.session_state.traffic_history.append({
                "Time": timestamp,
                "Inbound (MB/s)": in_mb,
                "Outbound (MB/s)": out_mb
            })
            if len(st.session_state.traffic_history) > 30:
                st.session_state.traffic_history.pop(0)
                
            # Draw inside empty placeholder
            with placeholder.container():
                df_history = pd.DataFrame(st.session_state.traffic_history)
                df_history.set_index("Time", inplace=True)
                
                # Check DDoS triggers with the slider thresholds
                pkts_in = t_stats["pkts_recv_ps"]
                bytes_in = t_stats["bytes_recv_ps"]
                
                ddos_active = False
                ddos_sev = "NORMAL"
                ddos_msg = ""
                
                if pkts_in > (st.session_state.packet_threshold * 5) or bytes_in > (st.session_state.byte_threshold_mb * 5 * 1024 * 1024):
                    ddos_active = True
                    ddos_sev = "CRITICAL"
                    ddos_msg = f"DDoS Trigger: Traffic exceeds CRITICAL levels ({format_bytes(bytes_in)}, {pkts_in} pkts/s)"
                elif pkts_in > st.session_state.packet_threshold or bytes_in > (st.session_state.byte_threshold_mb * 1024 * 1024):
                    ddos_active = True
                    ddos_sev = "WARNING"
                    ddos_msg = f"DDoS Warning: Traffic rate exceeds WARNING threshold ({format_bytes(bytes_in)}, {pkts_in} pkts/s)"
                
                st.markdown("#### Live Network Stats:")
                
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Live Download Speed", format_bytes(t_stats["bytes_recv_ps"]))
                m2.metric("Live Upload Speed", format_bytes(t_stats["bytes_sent_ps"]))
                m3.metric("Inbound Packets", f"{pkts_in} pkts/s")
                m4.metric("Outbound Packets", f"{t_stats['pkts_sent_ps']} pkts/s")
                
                if ddos_active:
                    ddos_box = "cyber-card-threat" if ddos_sev == "CRITICAL" else "cyber-card-warning"
                    st.markdown(f"""
                    <div class="{ddos_box}">
                        <h4 style="margin:0; color:#FF3B30;">🚨 DDOS ACTIVITY DETECTED [{ddos_sev}]</h4>
                        <p style="margin:5px 0 0 0; font-size:0.9rem;">{ddos_msg}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card-safe" style="padding:10px 15px;">
                        <span style="color:#00FF66;">✅ Traffic volumes are within limits. No DDoS anomaly detected.</span>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.area_chart(df_history)
                st.write("*This chart updates every second with active network interface rates.*")
                
                # Check for stop trigger (Streamlit handles reruns on interaction)
                time.sleep(0.1)
                
    # Historical / Static Report view
    if not st.session_state.live_monitoring:
        # Show traffic chart if history exists
        if st.session_state.traffic_history:
            st.markdown('<h4 class="neon-cyan">TRAFFIC SPEED ARCHIVE (MB/s)</h4>', unsafe_allow_html=True)
            df_history = pd.DataFrame(st.session_state.traffic_history)
            df_history.set_index("Time", inplace=True)
            st.area_chart(df_history)
            
        if st.session_state.network_analyzed and st.session_state.network_results:
            res = st.session_state.network_results
            
            # Displays DDoS / Port Scan alerts
            st.markdown('<h3 class="neon-sub-title">SECURITY THREAT DISCLOSURES</h3>', unsafe_allow_html=True)
            
            a1, a2 = st.columns(2)
            
            with a1:
                # DDoS
                if res['ddos_flagged']:
                    st.markdown(f"""
                    <div class="cyber-card-threat">
                        <h4 style="color:#FF3B30; margin:0;">🚨 DDoS Threshold Crossed</h4>
                        <p style="margin:5px 0 0 0; font-size:0.85rem;">{res['ddos_reason']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card-safe">
                        <h4 style="color:#00FF66; margin:0;">✅ DDoS Status: Normal</h4>
                        <p style="margin:5px 0 0 0; font-size:0.85rem;">Traffic rates comply with standard policies.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
            with a2:
                # Port Scan
                if res['port_scanners']:
                    st.markdown("""
                    <div class="cyber-card-warning">
                        <h4 style="color:#FFD700; margin:0;">🚨 Port Scan Activity Flagged</h4>
                        <p style="margin:5px 0 0 0; font-size:0.85rem;">One or more remote IPs hit more than 10 unique local ports.</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card-safe">
                        <h4 style="color:#00FF66; margin:0;">✅ Scan Status: Normal</h4>
                        <p style="margin:5px 0 0 0; font-size:0.85rem;">No multi-port probing scans identified.</p>
                    </div>
                    """, unsafe_allow_html=True)
            
            # Suspicious connections list
            sus_conns = res['suspicious_connections']
            if sus_conns:
                st.markdown('<h4 class="neon-red">⚠️ Flagged Suspicious Socket Connections</h4>', unsafe_allow_html=True)
                df_sus = pd.DataFrame([{
                    "PID": c["pid"],
                    "Process Name": c["process"],
                    "Remote Endpoint": f"{c['remote_ip']}:{c['remote_port']}",
                    "Local Port": c["local_port"],
                    "Status": c["status"],
                    "Risk Score": c["risk_score"],
                    "Analysis Reasons": ", ".join(c["reasons"])
                } for c in sus_conns])
                st.dataframe(df_sus, use_container_width=True)
            else:
                st.markdown("""
                <div class="cyber-card-safe" style="padding:10px 15px; margin-bottom:15px;">
                    <span style="color:#00FF66;">🛡️ No suspicious connections or unauthorized listeners detected.</span>
                </div>
                """, unsafe_allow_html=True)
                
            # Clean connection listings
            normal_conns = res['normal_connections']
            if normal_conns:
                st.markdown('<h4 class="neon-cyan">🌐 ACTIVE SOCKET CONNECTION TABLE</h4>', unsafe_allow_html=True)
                df_norm = pd.DataFrame([{
                    "Process Name": c["process"],
                    "Remote IP": c["remote_ip"],
                    "Remote Port": c["remote_port"],
                    "Local Port": c["local_port"],
                    "Connection Status": c["status"],
                    "PID": c["pid"]
                } for c in normal_conns])
                
                st.dataframe(df_norm, use_container_width=True)
        else:
            st.info("💡 Run a Connection Profile Scan or Start the Live Traffic Monitor to capture socket details.")
