import streamlit as st
import json
import os
import time
import pandas as pd


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cyber World Model",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# CSS
# ============================================================

st.markdown("""
<style>

/* Main container */
[data-testid="stAppViewContainer"] .main .block-container {
    padding-top: 0.3rem !important;
    padding-bottom: 0.5rem !important;
    padding-left: 1rem !important;
    padding-right: 1rem !important;
}

/* Reduce vertical gaps */
div[data-testid="stVerticalBlock"] {
    gap: 0.25rem !important;
}

/* Headings */
h1 {
    margin-top: 0 !important;
    margin-bottom: 0.2rem !important;
}

h2 {
    margin-top: 0.5rem !important;
    margin-bottom: 0.2rem !important;
}

h3 {
    margin-top: 0.3rem !important;
    margin-bottom: 0.15rem !important;
}

/* Markdown spacing */
div[data-testid="stMarkdownContainer"] {
    margin-bottom: 0 !important;
}

/* Metric spacing */
div[data-testid="stMetric"] {
    padding-top: 0 !important;
    padding-bottom: 0 !important;
}

/* Hide Streamlit menu/footer */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

/* Header */
[data-testid="stHeader"] {
    background-color: transparent;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# FILE
# ============================================================

STATE_FILE = "live_state.json"


# ============================================================
# LOAD LIVE STATE
# ============================================================

def load_state():

    if not os.path.exists(STATE_FILE):
        return None

    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)

    except Exception:
        return None


# ============================================================
# SESSION HISTORY
# ============================================================

if "history" not in st.session_state:
    st.session_state.history = []


# ============================================================
# TITLE
# ============================================================

st.markdown(
    """
    <h1 style="
        margin:0;
        padding:0;
        font-size:2.4rem;
        line-height:1.1;
    ">
        🛡️ Cyber World Model
    </h1>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <div style="
        font-size:1.05rem;
        margin-top:2px;
        margin-bottom:4px;
    ">
        Real-Time Network Traffic & AI Risk Monitoring
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# LOAD DATA
# ============================================================

data = load_state()


# ============================================================
# NO DATA
# ============================================================

if data is None:

    st.warning(
        "Waiting for live AI prediction... "
        "Start live_predictor.py first."
    )

    time.sleep(2)
    st.rerun()


# ============================================================
# VALUES
# ============================================================

risk = float(data.get("risk_percent", 0))
confidence = float(data.get("confidence_percent", 0))

attack_class = data.get("class", "Unknown")

source_ip = data.get("source_ip", "-")
destination_ip = data.get("destination_ip", "-")

source_port = data.get("source_port", "-")
destination_port = data.get("destination_port", "-")

protocol = data.get("protocol", "-")
service = data.get("service", "-")

duration = float(data.get("duration_ms", 0))
packet_count = int(data.get("packet_count", 0))
inter_arrival = float(data.get("inter_arrival_ms", 0))

matrix_shape = data.get("matrix_shape", [0, 0])


# ============================================================
# ADD CURRENT DATA TO HISTORY
# ============================================================

timestamp = float(data.get("timestamp", time.time()))

# Avoid adding exactly the same record repeatedly
if not st.session_state.history:

    st.session_state.history.append({
        "timestamp": timestamp,
        "risk": risk,
        "confidence": confidence,
        "duration": duration,
        "packet_count": packet_count,
        "inter_arrival": inter_arrival
    })

else:

    last_timestamp = st.session_state.history[-1]["timestamp"]

    if timestamp != last_timestamp:

        st.session_state.history.append({
            "timestamp": timestamp,
            "risk": risk,
            "confidence": confidence,
            "duration": duration,
            "packet_count": packet_count,
            "inter_arrival": inter_arrival
        })


# Keep last 50 observations
st.session_state.history = st.session_state.history[-50:]


history_df = pd.DataFrame(st.session_state.history)


# ============================================================
# RISK STATUS
# ============================================================

if risk < 30:

    risk_status = "LOW RISK"
    risk_icon = "🟢"

elif risk < 70:

    risk_status = "MODERATE RISK"
    risk_icon = "🟡"

else:

    risk_status = "HIGH RISK"
    risk_icon = "🔴"


# ============================================================
# AI SECURITY ASSESSMENT
# ============================================================

st.markdown("## 🤖 AI Security Assessment")

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Risk Score",
        f"{risk:.2f}%"
    )

with col2:

    st.metric(
        "AI Classification",
        attack_class
    )

with col3:

    st.metric(
        "AI Confidence",
        f"{confidence:.2f}%"
    )


# ============================================================
# STATUS BAR
# ============================================================

st.markdown(
    f"""
    <div style="
        padding:8px 14px;
        margin:3px 0 6px 0;
        border-left:5px solid #f5a623;
        background:#fff8e6;
        border-radius:6px;
        font-size:1.05rem;
        font-weight:600;
    ">
        {risk_icon} {risk_status}
        &nbsp;&nbsp;|&nbsp;&nbsp;
        AI Classification: {attack_class}
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# LIVE CONNECTION
# ============================================================

st.markdown("## 🌐 Live Network Connection")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.write("**Source IP**")
    st.write(source_ip)

    st.write("**Source Port**")
    st.write(source_port)

with col2:

    st.write("**Destination IP**")
    st.write(destination_ip)

    st.write("**Destination Port**")
    st.write(destination_port)

with col3:

    st.write("**Protocol**")
    st.write(protocol.upper())

    st.write("**Service**")
    st.write(service)

with col4:

    st.write("**Connection Duration**")
    st.write(f"{duration:.2f} ms")

    st.write("**Packet Count**")
    st.write(packet_count)


# ============================================================
# REAL-TIME TRAFFIC FEATURES
# ============================================================

st.markdown("## 📊 Real-Time Traffic Features")

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Connection Duration",
        f"{duration:.2f} ms"
    )

with col2:

    st.metric(
        "Packet Count",
        packet_count
    )

with col3:

    st.metric(
        "Inter-arrival Time",
        f"{inter_arrival:.2f} ms"
    )


# ============================================================
# GRAPH 1 — RISK SCORE
# ============================================================

st.markdown("## 📈 AI Risk Score")

risk_graph = history_df[
    ["risk"]
].rename(
    columns={
        "risk": "Risk Score (%)"
    }
)

risk_graph.index = range(
    1,
    len(risk_graph) + 1
)

st.line_chart(
    risk_graph,
    height=220,
    use_container_width=True
)


# ============================================================
# GRAPH 2 — AI CONFIDENCE
# ============================================================

st.markdown("## 🧠 AI Confidence")

confidence_graph = history_df[
    ["confidence"]
].rename(
    columns={
        "confidence": "Confidence (%)"
    }
)

confidence_graph.index = range(
    1,
    len(confidence_graph) + 1
)

st.line_chart(
    confidence_graph,
    height=220,
    use_container_width=True
)


# ============================================================
# GRAPH 3 — CONNECTION DURATION
# ============================================================

st.markdown("## ⏱️ Connection Duration")

duration_graph = history_df[
    ["duration"]
].rename(
    columns={
        "duration": "Duration (ms)"
    }
)

duration_graph.index = range(
    1,
    len(duration_graph) + 1
)

st.line_chart(
    duration_graph,
    height=220,
    use_container_width=True
)


# ============================================================
# GRAPH 4 — TRAFFIC BEHAVIOR
# ============================================================

st.markdown("## 📡 Traffic Behavior")

traffic_graph = history_df[
    ["packet_count", "inter_arrival"]
].rename(
    columns={
        "packet_count": "Packet Count",
        "inter_arrival": "Inter-arrival (ms)"
    }
)

traffic_graph.index = range(
    1,
    len(traffic_graph) + 1
)

st.line_chart(
    traffic_graph,
    height=240,
    use_container_width=True
)


# ============================================================
# AI TRAFFIC WINDOW
# ============================================================

st.markdown("## 🔢 AI Traffic Window")

st.write(
    f"Rolling traffic matrix: **{matrix_shape[0]} × {matrix_shape[1]}**"
)

matrix_df = pd.DataFrame(
    [
        {
            "Duration (ms)": duration,
            "Packets": packet_count,
            "Inter-arrival (ms)": inter_arrival
        }
    ]
)

st.dataframe(
    matrix_df,
    use_container_width=True,
    hide_index=True
)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div style="
        margin-top:5px;
        padding:6px;
        text-align:center;
        font-size:0.8rem;
        color:#666;
    ">
        🔄 Live data from Zeek → AI World Model → Dashboard
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# AUTO REFRESH
# ============================================================

time.sleep(2)
st.rerun()
