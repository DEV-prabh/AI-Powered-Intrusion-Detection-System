import os

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh  # <-- 1. Import autorefresh

# Paths
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

st.set_page_config(page_title='AI-Powered IDS Dashboard', layout='wide')

# --- 2. SETUP AUTO-REFRESH ---
# This refreshes the page every 2000 milliseconds (2 seconds)
st_autorefresh(interval=2000, key="ids_dashboard_refresh")

st.title('AI-Powered IDS for Home Networks')

# Live traffic stats
def load_packets():
    if os.path.exists(DATA_PATH):
        try:
            return pd.read_csv(DATA_PATH)
        except Exception: # Handle cases where file is being written to
            return pd.DataFrame()
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = f.readlines()
        return lines[-20:][::-1]
    return []

packets = load_packets()
col1, col2 = st.columns(2)

with col1:
    st.header('Live Traffic')
    st.write(f"Total packets captured: {len(packets)}")
    if not packets.empty:
        # Convert timestamp to a datetime object for proper grouping
        packets['timestamp'] = pd.to_datetime(packets['timestamp'])

        # Group by second to see the VOLUME (spikes) instead of just length
        traffic_volume = packets.resample('1S', on='timestamp').count()['src_ip']

        st.subheader("Traffic Volume (Packets per Second)")
        # This will now show "spikes" during an Nmap or DoS attack
        st.line_chart(traffic_volume.tail(60))

        st.subheader("Recent Raw Packets")
        st.dataframe(packets.tail(20), use_container_width=True)

with col2:
    st.header('Recent Alerts')
    alerts = load_alerts()
    if alerts:
        for alert in alerts:
            st.error(alert.strip())
    else:
        st.success('No suspicious activity detected.')

# Sidebar: Threat Intelligence (AbuseIPDB)
st.sidebar.header('Threat Intelligence (AbuseIPDB)')
last_abuse = None
for line in alerts:
    if line.startswith('AbuseIPDB:'):
        try:
            import ast
            abuse_data = ast.literal_eval(line[len('AbuseIPDB: '):].strip())
            last_abuse = abuse_data
            break
        except Exception:
            continue

if last_abuse:
    st.sidebar.metric("Latest Abuse Score", f"{last_abuse.get('abuseConfidenceScore')}%")
    st.sidebar.write(f"**IP:** {last_abuse.get('ip')}")
    st.sidebar.write(f"**Country:** {last_abuse.get('countryCode')}")
    st.sidebar.write(f"**ISP:** {last_abuse.get('isp', 'N/A')}")
    st.sidebar.write(f"**Domain:** {last_abuse.get('domain')}")
    if last_abuse.get('abuseConfidenceScore', 0) >= 50:
        st.sidebar.error('🚨 HIGH RISK IP AUTO-BLOCKED')
else:
    st.sidebar.info('No recent external threats detected.')

st.caption('AI-Powered IDS | Real-time Streamlit Dashboard')
