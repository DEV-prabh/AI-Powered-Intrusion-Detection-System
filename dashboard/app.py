import os
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Paths
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
ALERTS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.csv')
WHITELIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'whitelist.txt')

st.set_page_config(
    page_title='AI-Powered IDS Dashboard',
    layout='wide',
    initial_sidebar_state='expanded'
)

# Custom CSS for better visibility and dark theme + Smooth transitions
st.markdown("""
<style>
    /* Fix font visibility */
    .stApp {
        background-color: #0e1117;
        color: #ffffff;
    }

    /* Make all text visible */
    p, span, div, label, h1, h2, h3, h4, h5, h6 {
        color: #ffffff !important;
    }

    /* Metric styling */
    .stMetric {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 20px;
        border-radius: 10px;
        color: white !important;
    }

    .stMetric label {
        color: #e0e7ff !important;
        font-size: 16px !important;
        font-weight: 600 !important;
    }

    .stMetric [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 32px !important;
        font-weight: bold !important;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #1f2937;
        padding: 10px;
        border-radius: 10px;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: #374151;
        color: #ffffff !important;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: 600;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
        color: #ffffff !important;
    }

    /* Alert styling */
    .alert-critical {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border-left: 5px solid #ef4444;
    }

    .alert-high {
        background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border-left: 5px solid #f97316;
    }

    .alert-medium {
        background: linear-gradient(135deg, #ca8a04 0%, #a16207 100%);
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border-left: 5px solid #eab308;
    }

    .alert-low {
        background: linear-gradient(135deg, #16a34a 0%, #15803d 100%);
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border-left: 5px solid #22c55e;
    }

    /* Dataframe styling */
    .stDataFrame {
        background-color: #1f2937 !important;
    }

    /* Button styling */
    .stButton button {
        background-color: #3b82f6;
        color: white !important;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 600;
    }

    .stButton button:hover {
        background-color: #2563eb;
    }
    
    /* Prevent page flash on reload */
    .stApp > header {
        background-color: transparent;
    }
    
    /* Smooth fade for content */
    .element-container {
        animation: fadeIn 0.3s ease-in;
    }
    
    @keyframes fadeIn {
        from { opacity: 0.8; }
        to { opacity: 1; }
    }
</style>

<script>
// Auto-refresh without full page reload
let refreshInterval;

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        // Trigger Streamlit rerun smoothly
        const buttons = window.parent.document.querySelectorAll('button[kind="primary"]');
        buttons.forEach(button => {
            if (button.textContent.includes('Rerun')) {
                button.click();
            }
        });
    }, 5000); // Refresh every 5 seconds
}

// Start auto-refresh when page loads
if (document.readyState === 'complete') {
    startAutoRefresh();
} else {
    window.addEventListener('load', startAutoRefresh);
}
</script>
""", unsafe_allow_html=True)

# Load data functions - No caching to get fresh data
def load_packets():
    if os.path.exists(DATA_PATH):
        try:
            df = pd.read_csv(DATA_PATH)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
            return df
        except Exception as e:
            return pd.DataFrame()
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(ALERTS_PATH):
        try:
            df = pd.read_csv(ALERTS_PATH)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['timestamp'])
            return df
        except Exception as e:
            return pd.DataFrame()
    return pd.DataFrame()

def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            return []
    return []

def save_whitelist(ips):
    try:
        os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
        with open(WHITELIST_PATH, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
    except Exception as e:
        pass

# Initialize session state for smooth updates
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()
if 'refresh_counter' not in st.session_state:
    st.session_state.refresh_counter = 0

# Load data
packets = load_packets()
alerts = load_alerts()
whitelist = load_whitelist()

# Update counter
st.session_state.refresh_counter += 1
st.session_state.last_update = datetime.now()

# === TITLE ===
col_title, col_refresh = st.columns([6, 1])
with col_title:
    st.markdown("<h1 style='color: #60a5fa; font-size: 48px;'>🛡️ AI-Powered IDS</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #9ca3af; font-size: 18px;'>Real-time Network Security Monitoring</p>", unsafe_allow_html=True)
with col_refresh:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

st.markdown("---")

# === TOP METRICS ROW ===
col1, col2, col3, col4 = st.columns(4)

with col1:
    total_packets = len(packets) if not packets.empty else 0
    st.metric("📊 Total Packets", f"{total_packets:,}")

with col2:
    total_alerts = len(alerts) if not alerts.empty else 0
    st.metric("🚨 Total Alerts", f"{total_alerts:,}")

with col3:
    if not alerts.empty:
        high_risk = len(alerts[alerts['abuse_score'] >= 75])
        st.metric("⚠️ High Risk", f"{high_risk}")
    else:
        st.metric("⚠️ High Risk", "0")

with col4:
    if not packets.empty:
        try:
            recent_packets = packets[packets['timestamp'] > (datetime.now() - timedelta(seconds=10))]
            pps = len(recent_packets)
            st.metric("⚡ Packets/10s", f"{pps}")
        except Exception:
            st.metric("⚡ Packets/10s", "0")
    else:
        st.metric("⚡ Packets/10s", "0")

st.markdown("---")

# === MAIN CONTENT ===
tab1, tab2, tab3, tab4 = st.tabs(["📈 Live Traffic", "🚨 Alerts", "🌍 Threat Map", "⚙️ Settings"])

with tab1:
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("<h3 style='color: #60a5fa;'>Traffic Volume Over Time</h3>", unsafe_allow_html=True)
        
        # Create placeholder for smooth updates
        chart_placeholder = st.empty()
        
        if not packets.empty:
            try:
                cutoff_time = datetime.now() - timedelta(minutes=5)
                recent_packets = packets[packets['timestamp'] > cutoff_time].copy()

                if not recent_packets.empty and len(recent_packets) > 1:
                    traffic_volume = recent_packets.set_index('timestamp').resample('500ms').size()

                    if len(traffic_volume) > 0:
                        baseline = traffic_volume.mean()
                        std_dev = traffic_volume.std()
                        
                        if std_dev == 0 or pd.isna(std_dev):
                            threshold = baseline + 5
                        else:
                            threshold = baseline + (2 * std_dev)

                        fig = go.Figure()

                        fig.add_trace(go.Scatter(
                            x=traffic_volume.index,
                            y=traffic_volume.values,
                            mode='lines',
                            fill='tozeroy',
                            line=dict(color='#3b82f6', width=2),
                            name='Traffic',
                            fillcolor='rgba(59, 130, 246, 0.3)'
                        ))

                        attack_indices = traffic_volume[traffic_volume > threshold]
                        if not attack_indices.empty and len(attack_indices) > 0:
                            fig.add_trace(go.Scatter(
                                x=attack_indices.index,
                                y=attack_indices.values,
                                mode='markers',
                                marker=dict(color='#ef4444', size=10, symbol='triangle-up'),
                                name='Spike',
                            ))

                        fig.add_hline(
                            y=threshold,
                            line_dash="dash",
                            line_color="#fbbf24",
                            annotation_text="Threshold",
                            annotation_position="right"
                        )

                        fig.update_layout(
                            height=400,
                            margin=dict(l=0, r=0, t=30, b=0),
                            xaxis_title="Time",
                            yaxis_title="Packets/0.5s",
                            hovermode='x unified',
                            plot_bgcolor='#1f2937',
                            paper_bgcolor='#1f2937',
                            font=dict(color='#ffffff', size=14),
                            xaxis=dict(gridcolor='#374151', color='#ffffff'),
                            yaxis=dict(gridcolor='#374151', color='#ffffff'),
                            legend=dict(bgcolor='#374151', font=dict(color='#ffffff')),
                            transition={'duration': 500}
                        )
                        
                        with chart_placeholder:
                            st.plotly_chart(fig, use_container_width=True, key=f"traffic_chart_{st.session_state.refresh_counter}")

                        col_s1, col_s2, col_s3 = st.columns(3)
                        with col_s1:
                            st.markdown(f"<p style='color: #60a5fa; font-size: 16px;'>Avg: <b>{baseline:.1f}</b></p>", unsafe_allow_html=True)
                        with col_s2:
                            st.markdown(f"<p style='color: #fbbf24; font-size: 16px;'>Threshold: <b>{threshold:.1f}</b></p>", unsafe_allow_html=True)
                        with col_s3:
                            spike_count = len(attack_indices)
                            st.markdown(f"<p style='color: #ef4444; font-size: 16px;'>Spikes: <b>{spike_count}</b></p>", unsafe_allow_html=True)
                    else:
                        with chart_placeholder:
                            st.info("Collecting data points...")
                else:
                    with chart_placeholder:
                        st.info("Waiting for packets (need 2+)...")
            except Exception as e:
                with chart_placeholder:
                    st.warning(f"Graph loading... ({str(e)[:50]})")
        else:
            with chart_placeholder:
                st.info("Start sniffer.py to see traffic!")

    with col_right:
        st.markdown("<h3 style='color: #60a5fa;'>Protocol Distribution</h3>", unsafe_allow_html=True)
        
        proto_placeholder = st.empty()
        
        if not packets.empty and 'protocol' in packets.columns:
            try:
                proto_counts = packets['protocol'].value_counts()
                if len(proto_counts) > 0:
                    fig = px.pie(
                        values=proto_counts.values,
                        names=proto_counts.index,
                        color_discrete_sequence=['#3b82f6', '#8b5cf6', '#ec4899', '#10b981']
                    )
                    fig.update_layout(
                        height=400,
                        margin=dict(l=0, r=0, t=0, b=0),
                        plot_bgcolor='#1f2937',
                        paper_bgcolor='#1f2937',
                        font=dict(color='#ffffff', size=14),
                        legend=dict(bgcolor='#374151', font=dict(color='#ffffff'))
                    )
                    fig.update_traces(textfont=dict(color='#ffffff', size=16))
                    
                    with proto_placeholder:
                        st.plotly_chart(fig, use_container_width=True, key=f"proto_chart_{st.session_state.refresh_counter}")
                else:
                    with proto_placeholder:
                        st.info("No protocol data")
            except Exception:
                with proto_placeholder:
                    st.info("Loading protocols...")
        else:
            with proto_placeholder:
                st.info("No protocol data")

    st.markdown("<h3 style='color: #60a5fa; margin-top: 30px;'>Recent Packets</h3>", unsafe_allow_html=True)
    
    packets_placeholder = st.empty()
    
    if not packets.empty:
        try:
            display_df = packets.tail(50).sort_values('timestamp', ascending=False)
            with packets_placeholder:
                st.dataframe(
                    display_df[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_length']],
                    use_container_width=True,
                    height=350,
                    key=f"packets_table_{st.session_state.refresh_counter}"
                )
        except Exception:
            with packets_placeholder:
                st.info("Loading packets...")
    else:
        with packets_placeholder:
            st.info("No packets yet")

with tab2:
    st.markdown("<h2 style='color: #60a5fa;'>Security Alerts</h2>", unsafe_allow_html=True)

    if not alerts.empty:
        col_f1, col_f2, col_f3 = st.columns(3)

        with col_f1:
            severity_filter = st.selectbox(
                "Severity Level",
                ["All", "Critical (75+)", "High (50-74)", "Medium (25-49)", "Low (<25)"],
                key="severity_filter"
            )

        with col_f2:
            attack_types = ["All"] + sorted(alerts['attack'].unique().tolist())
            attack_filter = st.selectbox("Attack Type", attack_types, key="attack_filter")

        with col_f3:
            time_filter = st.selectbox(
                "Time Range",
                ["Last Hour", "Last 6 Hours", "Last 24 Hours", "All Time"],
                key="time_filter"
            )

        filtered_alerts = alerts.copy()

        if severity_filter == "Critical (75+)":
            filtered_alerts = filtered_alerts[filtered_alerts['abuse_score'] >= 75]
        elif severity_filter == "High (50-74)":
            filtered_alerts = filtered_alerts[(filtered_alerts['abuse_score'] >= 50) & (filtered_alerts['abuse_score'] < 75)]
        elif severity_filter == "Medium (25-49)":
            filtered_alerts = filtered_alerts[(filtered_alerts['abuse_score'] >= 25) & (filtered_alerts['abuse_score'] < 50)]
        elif severity_filter == "Low (<25)":
            filtered_alerts = filtered_alerts[filtered_alerts['abuse_score'] < 25]

        if attack_filter != "All":
            filtered_alerts = filtered_alerts[filtered_alerts['attack'] == attack_filter]

        if time_filter == "Last Hour":
            filtered_alerts = filtered_alerts[filtered_alerts['timestamp'] > (datetime.now() - timedelta(hours=1))]
        elif time_filter == "Last 6 Hours":
            filtered_alerts = filtered_alerts[filtered_alerts['timestamp'] > (datetime.now() - timedelta(hours=6))]
        elif time_filter == "Last 24 Hours":
            filtered_alerts = filtered_alerts[filtered_alerts['timestamp'] > (datetime.now() - timedelta(hours=24))]

        st.markdown(f"<p style='color: #ffffff; font-size: 18px;'>Showing <b>{len(filtered_alerts)}</b> alerts</p>", unsafe_allow_html=True)

        for idx, row in filtered_alerts.sort_values('timestamp', ascending=False).head(20).iterrows():
            if row['abuse_score'] >= 75:
                severity_class = "alert-critical"
                severity_emoji = "🔴"
                severity_text = "CRITICAL"
            elif row['abuse_score'] >= 50:
                severity_class = "alert-high"
                severity_emoji = "🟠"
                severity_text = "HIGH"
            elif row['abuse_score'] >= 25:
                severity_class = "alert-medium"
                severity_emoji = "🟡"
                severity_text = "MEDIUM"
            else:
                severity_class = "alert-low"
                severity_emoji = "🟢"
                severity_text = "LOW"

            with st.container():
                st.markdown(f"""
                <div class="{severity_class}">
                    <p style="font-size: 18px; font-weight: bold; margin-bottom: 5px;">
                        {severity_emoji} {severity_text} - {row['attack']}
                    </p>
                    <p style="margin: 5px 0;">
                        <b>Source:</b> {row['src_ip']} → <b>Dest:</b> {row['dst_ip']}
                    </p>
                    <p style="margin: 5px 0;">
                        🌍 {row['country']} | 🏢 {row['isp']} | 📊 Score: {row['abuse_score']}%
                    </p>
                    <p style="margin: 5px 0; opacity: 0.8;">
                        🕐 {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
                """, unsafe_allow_html=True)

                col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 8])
                with col_btn1:
                    if st.button("✅ Whitelist", key=f"wl_{idx}_{st.session_state.refresh_counter}"):
                        if row['src_ip'] not in whitelist:
                            whitelist.append(row['src_ip'])
                            save_whitelist(whitelist)
                            st.success(f"✅ {row['src_ip']} whitelisted")
                            st.rerun()

                st.markdown("<br>", unsafe_allow_html=True)
    else:
        st.success("✅ No alerts detected!")

with tab3:
    st.markdown("<h2 style='color: #60a5fa;'>Geographic Threat Distribution</h2>", unsafe_allow_html=True)

    if not alerts.empty and 'country' in alerts.columns:
        try:
            country_counts = alerts['country'].value_counts().head(10)

            fig = px.bar(
                x=country_counts.values,
                y=country_counts.index,
                orientation='h',
                labels={'x': 'Alerts', 'y': 'Country'},
                color=country_counts.values,
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                height=400,
                plot_bgcolor='#1f2937',
                paper_bgcolor='#1f2937',
                font=dict(color='#ffffff', size=14),
                xaxis=dict(gridcolor='#374151', color='#ffffff'),
                yaxis=dict(gridcolor='#374151', color='#ffffff')
            )
            st.plotly_chart(fig, use_container_width=True, key=f"geo_chart_{st.session_state.refresh_counter}")

            st.markdown("<h3 style='color: #60a5fa;'>Top Threat Sources</h3>", unsafe_allow_html=True)
            threat_sources = alerts.groupby('src_ip').agg({
                'attack': 'count',
                'abuse_score': 'mean',
                'country': 'first',
                'isp': 'first'
            }).sort_values('attack', ascending=False).head(10)
            threat_sources.columns = ['Attacks', 'Avg Score', 'Country', 'ISP']
            st.dataframe(threat_sources, use_container_width=True, height=400)
        except Exception:
            st.info("Loading threat data...")
    else:
        st.info("No geographic data yet")

with tab4:
    st.markdown("<h2 style='color: #60a5fa;'>System Settings</h2>", unsafe_allow_html=True)

    col_s1, col_s2 = st.columns(2)

    with col_s1:
        st.markdown("<h3 style='color: #60a5fa;'>Whitelisted IPs</h3>", unsafe_allow_html=True)
        if whitelist:
            for ip in whitelist:
                col_ip, col_btn = st.columns([3, 1])
                with col_ip:
                    st.code(ip)
                with col_btn:
                    if st.button("🗑️", key=f"rm_{ip}_{st.session_state.refresh_counter}"):
                        whitelist.remove(ip)
                        save_whitelist(whitelist)
                        st.rerun()
        else:
            st.info("No whitelisted IPs")

        new_ip = st.text_input("Add IP to whitelist:", key="new_ip_input")
        if st.button("➕ Add"):
            if new_ip and new_ip not in whitelist:
                whitelist.append(new_ip)
                save_whitelist(whitelist)
                st.success(f"✅ Added {new_ip}")
                st.rerun()

    with col_s2:
        st.markdown("<h3 style='color: #60a5fa;'>System Status</h3>", unsafe_allow_html=True)
        
        sniffer_status = "🟢 Active" if os.path.exists(DATA_PATH) and os.path.getsize(DATA_PATH) > 0 else "🔴 Inactive"
        detection_status = "🟢 Running" if os.path.exists(ALERTS_PATH) else "🔴 Not Running"
        
        st.metric("Dashboard", "🟢 Active")
        st.metric("Detection", detection_status)
        st.metric("Sniffer", sniffer_status)

        if st.button("🗑️ Clear Alerts"):
            if os.path.exists(ALERTS_PATH):
                os.remove(ALERTS_PATH)
                st.success("Cleared!")
                st.rerun()

# Sidebar
st.sidebar.markdown("<h2 style='color: #60a5fa;'>📊 Quick Stats</h2>", unsafe_allow_html=True)

if not alerts.empty:
    try:
        recent_alerts = alerts[alerts['timestamp'] > (datetime.now() - timedelta(hours=1))]
        st.sidebar.metric("Last Hour", len(recent_alerts))

        if len(recent_alerts) > 0:
            high_risk_recent = len(recent_alerts[recent_alerts['abuse_score'] >= 75])
            st.sidebar.metric("High Risk", high_risk_recent)

            top_attacker = recent_alerts['src_ip'].value_counts().head(1)
            if not top_attacker.empty:
                st.sidebar.markdown("<p style='color: #ffffff;'><b>Top Attacker:</b></p>", unsafe_allow_html=True)
                st.sidebar.code(top_attacker.index[0])
                st.sidebar.caption(f"{top_attacker.values[0]} attacks")
    except Exception:
        pass

st.sidebar.markdown("---")
st.sidebar.markdown("<p style='color: #9ca3af;'>🛡️ AI-Powered IDS v2.0</p>", unsafe_allow_html=True)
st.sidebar.markdown(f"<p style='color: #9ca3af;'>Updated: {st.session_state.last_update.strftime('%H:%M:%S')}</p>", unsafe_allow_html=True)

# Auto-refresh mechanism using Streamlit's built-in rerun
import time
time.sleep(5)  # Wait 5 seconds
st.rerun()