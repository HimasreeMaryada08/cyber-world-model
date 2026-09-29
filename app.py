import os
import json
import streamlit as st
import time
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cyber World Model - Live Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# FILE CONFIGURATION
# ============================================================

STATE_FILE = "/home/himasreereddy/zeek-live/live_state.json"


# ============================================================
# SESSION STATE
# ============================================================

if "history" not in st.session_state:
    st.session_state.history = []

if "last_timestamp" not in st.session_state:
    st.session_state.last_timestamp = None


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 34px;
        font-weight: 700;
        margin-bottom: 0px;
    }

    .sub-title {
        font-size: 16px;
        color: #666666;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 24px;
        font-weight: 650;
        margin-top: 20px;
        margin-bottom: 10px;
    }

    .status-box {
        padding: 14px;
        border-radius: 10px;
        text-align: center;
        font-size: 20px;
        font-weight: 600;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# READ LIVE STATE
# ============================================================

def read_live_state():

    if not os.path.exists(STATE_FILE):
        return None

    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)

    except Exception:
        return None


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Cyber World Model</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">Real-Time Network Traffic & AI Risk Monitoring</div>',
    unsafe_allow_html=True
)


# ============================================================
# LIVE DASHBOARD REFRESH
# ============================================================

@st.fragment(run_every="2s")
def live_dashboard():

    data = read_live_state()

    if data is None:
        st.warning(
            "Waiting for live_state.json... "
            "Start live_predictor.py first."
        )
        st.stop()

    # ============================================================
    # CURRENT VALUES
    # ============================================================

    timestamp = data.get("timestamp", time.time())

    duration = float(data.get("duration_ms", 0))
    packets = int(data.get("packet_count", 0))
    inter_arrival = float(data.get("inter_arrival_ms", 0))

    risk = float(data.get("risk_percent") if data.get("risk_percent") is not None else (data.get("risk") or 0) * 100)

    if risk <= 1:
        risk = risk * 100

    confidence = float(
        data.get(
            "confidence_percent",
            (data.get("confidence") or 0) * 100
        )
    )

    if confidence <= 1:
        confidence = confidence * 100


    # ============================================================
    # ADD NEW DATA TO HISTORY
    # ============================================================

    if (
        st.session_state.last_timestamp is None
        or timestamp != st.session_state.last_timestamp
    ):

        record = {
            "timestamp": timestamp,
            "time": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
            "duration": duration,
            "packets": packets,
            "inter_arrival": inter_arrival,
            "risk": risk,
            "confidence": confidence
        }

        st.session_state.history.append(record)

        st.session_state.last_timestamp = timestamp


    # Keep only latest 50 observations

    st.session_state.history = st.session_state.history[-50:]


    df = pd.DataFrame(st.session_state.history)


    # ============================================================
    # CURRENT STATUS
    # ============================================================

    threat_class = data.get("class", "Unknown")

    source_ip = data.get("source_ip", "-")
    destination_ip = data.get("destination_ip", "-")
    source_port = data.get("source_port", "-")
    destination_port = data.get("destination_port", "-")
    protocol = data.get("protocol", "-")
    service = data.get("service", "-")


    # ============================================================
    # TOP STATUS CARDS
    # ============================================================

    st.markdown(
        '<div class="section-title">📊 Current AI Assessment</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "AI Risk Score",
            f"{risk:.2f}%"
        )

    with c2:
        st.metric(
            "AI Confidence",
            f"{confidence:.2f}%"
        )

    with c3:
        st.metric(
            "Attack Class",
            threat_class
        )

    with c4:

        if risk < 30:
            status = "LOW RISK"
        elif risk < 60:
            status = "MODERATE RISK"
        elif risk < 80:
            status = "HIGH RISK"
        else:
            status = "CRITICAL RISK"

        st.metric(
            "Threat Status",
            status
        )


    # ============================================================
    # RISK STATUS MESSAGE
    # ============================================================

    if risk < 30:

        st.success(
            f"🟢 Network currently appears normal — AI risk {risk:.2f}%"
        )

    elif risk < 60:

        st.warning(
            f"🟡 Network requires monitoring — AI risk {risk:.2f}%"
        )

    elif risk < 80:

        st.warning(
            f"🟠 Elevated network risk detected — AI risk {risk:.2f}%"
        )

    else:

        st.error(
            f"🔴 High risk condition detected — AI risk {risk:.2f}%"
        )


    # ============================================================
    # LIVE CONNECTION DETAILS
    # ============================================================

    st.markdown(
        '<div class="section-title">🌐 Latest Network Connection</div>',
        unsafe_allow_html=True
    )

    d1, d2, d3, d4 = st.columns(4)

    with d1:
        st.write("**Source IP**")
        st.code(source_ip)

        st.write("**Source Port**")
        st.code(str(source_port))

    with d2:
        st.write("**Destination IP**")
        st.code(destination_ip)

        st.write("**Destination Port**")
        st.code(str(destination_port))

    with d3:
        st.write("**Protocol**")
        st.code(str(protocol).upper())

        st.write("**Service**")
        st.code(str(service))

    with d4:
        st.write("**Duration**")
        st.metric(
            "Connection Duration",
            f"{duration:.2f} ms"
        )

        st.write("**Packets**")
        st.metric(
            "Packet Count",
            str(packets)
        )


    # ============================================================
    # TRAFFIC FEATURE GRAPHS
    # ============================================================

    st.markdown(
        '<div class="section-title">📈 Real-Time Traffic Features</div>',
        unsafe_allow_html=True
    )


    # ------------------------------------------------------------
    # GRAPH 1 — CONNECTION DURATION
    # ------------------------------------------------------------

    fig_duration = go.Figure()

    fig_duration.add_trace(
        go.Scatter(
            x=df["time"],
            y=df["duration"],
            mode="lines+markers",
            name="Duration",
            line=dict(width=3),
            marker=dict(size=6)
        )
    )

    fig_duration.update_layout(
        title="Connection Duration",
        xaxis_title="Time",
        yaxis_title="Duration (ms)",
        height=330,
        margin=dict(l=40, r=20, t=60, b=40),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_duration,
        use_container_width=True
    )


    # ------------------------------------------------------------
    # GRAPH 2 — PACKET COUNT
    # ------------------------------------------------------------

    fig_packets = go.Figure()

    fig_packets.add_trace(
        go.Scatter(
            x=df["time"],
            y=df["packets"],
            mode="lines+markers",
            name="Packets",
            line=dict(width=3),
            marker=dict(size=6)
        )
    )

    fig_packets.update_layout(
        title="Packet Count Trend",
        xaxis_title="Time",
        yaxis_title="Packets",
        height=330,
        margin=dict(l=40, r=20, t=60, b=40),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_packets,
        use_container_width=True
    )


    # ------------------------------------------------------------
    # GRAPH 3 — INTER-ARRIVAL TIME
    # ------------------------------------------------------------

    fig_inter = go.Figure()

    fig_inter.add_trace(
        go.Scatter(
            x=df["time"],
            y=df["inter_arrival"],
            mode="lines+markers",
            name="Inter-arrival",
            line=dict(width=3),
            marker=dict(size=6)
        )
    )

    fig_inter.update_layout(
        title="Inter-arrival Time Trend",
        xaxis_title="Time",
        yaxis_title="Inter-arrival Time (ms)",
        height=330,
        margin=dict(l=40, r=20, t=60, b=40),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_inter,
        use_container_width=True
    )


    # ============================================================
    # AI RISK VISUALIZATION
    # ============================================================

    st.markdown(
        '<div class="section-title">🤖 AI Risk Visualization</div>',
        unsafe_allow_html=True
    )


    # ------------------------------------------------------------
    # GRAPH 4 — RISK TREND
    # ------------------------------------------------------------

    fig_risk = go.Figure()

    fig_risk.add_trace(
        go.Scatter(
            x=df["time"],
            y=df["risk"],
            mode="lines+markers",
            name="AI Risk",
            line=dict(width=4),
            marker=dict(size=7)
        )
    )

    # Risk threshold lines

    fig_risk.add_hline(
        y=30,
        line_dash="dash",
        annotation_text="Low → Moderate"
    )

    fig_risk.add_hline(
        y=60,
        line_dash="dash",
        annotation_text="Moderate → High"
    )

    fig_risk.add_hline(
        y=80,
        line_dash="dash",
        annotation_text="High → Critical"
    )

    fig_risk.update_layout(
        title="AI Risk Score Over Time",
        xaxis_title="Time",
        yaxis_title="Risk Score (%)",
        yaxis=dict(
            range=[0, 100]
        ),
        height=400,
        margin=dict(l=50, r=30, t=70, b=50),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_risk,
        use_container_width=True
    )


    # ============================================================
    # RISK CHANGE
    # ============================================================

    if len(df) >= 2:

        current_risk = df["risk"].iloc[-1]
        previous_risk = df["risk"].iloc[-2]

        risk_change = current_risk - previous_risk

    else:

        risk_change = 0


    if risk_change > 0:

        change_text = f"↑ {risk_change:.2f}%"

    elif risk_change < 0:

        change_text = f"↓ {abs(risk_change):.2f}%"

    else:

        change_text = "→ 0.00%"


    st.metric(
        "Risk Change",
        change_text,
        delta=f"{risk_change:.2f} percentage points"
    )


    # ============================================================
    # GRAPH 5 — RISK CHANGE HISTORY
    # ============================================================

    df["risk_change"] = df["risk"].diff().fillna(0)


    fig_change = go.Figure()

    fig_change.add_trace(
        go.Bar(
            x=df["time"],
            y=df["risk_change"],
            name="Risk Change"
        )
    )

    fig_change.add_hline(
        y=0,
        line_dash="solid"
    )

    fig_change.update_layout(
        title="Risk Change Between Connections",
        xaxis_title="Time",
        yaxis_title="Change in Risk (percentage points)",
        height=350,
        margin=dict(l=50, r=30, t=60, b=50),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_change,
        use_container_width=True
    )


    # ============================================================
    # FUTURE ATTACK FORECAST
    # ============================================================
    
    st.markdown(
        '<div class="section-title">🔮 Future Attack Forecast</div>',
        unsafe_allow_html=True
    )
    
    
    forecast = data.get(
        "forecast",
        []
    )
    
    
    if forecast:
    
        forecast_rows = []
    
    
        for item in forecast:
    
            forecast_rows.append(
                {
                    "Step": f"+{item.get('step', 0)}",
                    "Risk": float(
                        item.get(
                            "risk_percent",
                            item.get("risk", 0) * 100
                        )
                    ),
                    "Class": item.get(
                        "class",
                        "Unknown"
                    ),
                    "Confidence": float(
                        item.get(
                            "confidence_percent",
                            item.get("confidence", 0) * 100
                        )
                    )
                }
            )
    
    
        forecast_df = pd.DataFrame(
            forecast_rows
        )
    
    
        # --------------------------------------------------------
        # FORECAST RISK GRAPH
        # --------------------------------------------------------
    
        fig_forecast = go.Figure()
    
    
        fig_forecast.add_trace(
            go.Scatter(
                x=forecast_df["Step"],
                y=forecast_df["Risk"],
                mode="lines+markers",
                name="Forecast Risk"
            )
        )
    
    
        fig_forecast.add_hline(
            y=60,
            line_dash="dash",
            annotation_text="Elevated"
        )
    
    
        fig_forecast.add_hline(
            y=80,
            line_dash="dash",
            annotation_text="High"
        )
    
    
        fig_forecast.update_layout(
            title="Multi-Step Future Risk Forecast",
            xaxis_title="Future Step",
            yaxis_title="Predicted Risk (%)",
            yaxis=dict(
                range=[0, 100]
            ),
            height=350,
            margin=dict(
                l=50,
                r=20,
                t=60,
                b=45
            )
        )
    
    
        st.plotly_chart(
            fig_forecast,
            use_container_width=True
        )
    
    
        # --------------------------------------------------------
        # FORECAST TABLE
        # --------------------------------------------------------
    
        st.dataframe(
            forecast_df,
            use_container_width=True,
            hide_index=True
        )
    
    
        # --------------------------------------------------------
        # HIGHEST FUTURE RISK
        # --------------------------------------------------------
    
        highest_forecast = max(
            forecast,
            key=lambda item: float(
                item.get(
                    "risk_percent",
                    item.get("risk", 0) * 100
                )
            )
        )
    
    
        future_risk = float(
            highest_forecast.get(
                "risk_percent",
                highest_forecast.get(
                    "risk",
                    0
                ) * 100
            )
        )
    
    
        future_class = highest_forecast.get(
            "class",
            "Unknown"
        )
    
    
        future_step = highest_forecast.get(
            "step",
            0
        )
    
    
        st.markdown(
            "**🔮 Forecast-based warning**"
        )
    
    
        if future_risk >= 80:
    
            st.error(
                f"🔴 The model forecasts HIGH risk at "
                f"+{future_step} step: "
                f"**{future_risk:.2f}%** "
                f"with predicted class "
                f"**{future_class}**."
            )
    
    
        elif future_risk >= 70:
    
            st.warning(
                f"⚠️ The model forecasts elevated risk at "
                f"+{future_step} step: "
                f"**{future_risk:.2f}%** "
                f"with predicted class "
                f"**{future_class}**."
            )
    
    
        elif future_risk >= 60:
    
            st.warning(
                f"🟠 The model forecasts increasing risk at "
                f"+{future_step} step: "
                f"**{future_risk:.2f}%** "
                f"with predicted class "
                f"**{future_class}**."
            )
    
    
        else:
    
            st.success(
                f"🟢 Forecast risk remains below the "
                f"elevated threshold. Highest predicted "
                f"risk is **{future_risk:.2f}%**."
            )
    
    
    else:
    
        st.info(
            "🔮 Future attack forecast will appear "
            "after a complete AI traffic window is available."
        )
    
    
    # ============================================================
    # AI TRAFFIC WINDOW
    # ============================================================
    
    st.markdown(
        '<div class="section-title">🧮 AI Traffic Window</div>',
        unsafe_allow_html=True
    )
    
    
    matrix_shape = data.get(
        "matrix_shape",
        []
    )
    
    
    if matrix_shape:
    
        st.write(
            f"Current AI input matrix: "
            f"**{matrix_shape[0]} × {matrix_shape[1]}**"
        )
    
    
        matrix_rows = data.get(
            "matrix",
            []
        )
    
    
        if matrix_rows:
    
            matrix_array = np.asarray(
                matrix_rows
            )
    
    
            matrix_df = pd.DataFrame(
                matrix_array,
                columns=[
                    "Duration (ms)",
                    "Packet Count",
                    "Inter-arrival (ms)"
                ]
            )
    
    
            st.dataframe(
                matrix_df,
                use_container_width=True,
                height=300
            )
    
    
        else:
    
            st.info(
                "Traffic matrix values are not stored "
                "in live_state.json. Matrix shape is "
                f"{matrix_shape[0]} × {matrix_shape[1]}."
            )
    
    
    else:
    
        st.info(
            "AI traffic window information is not available yet."
        )
    
    
    # ============================================================
    # CURRENT PREDICTION DETAILS
    # ============================================================
    
    st.markdown(
        '<div class="section-title">🧠 Current AI Decision</div>',
        unsafe_allow_html=True
    )
    
    
    decision_1, decision_2, decision_3 = st.columns(3)
    
    
    with decision_1:
    
        st.metric(
            "Risk",
            f"{risk:.2f}%"
        )
    
    
    with decision_2:
    
        st.metric(
            "Class",
            data.get("class", "Unknown")
        )
    
    
    with decision_3:
    
        st.metric(
            "Confidence",
            f"{confidence:.2f}%"
        )
    
    
    # ============================================================
    # TIMESTAMP
    # ============================================================
    
    try:
    
        readable_time = datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    
    except Exception:
    
        readable_time = "-"
    
    
    st.caption(
        f"Last AI update: {readable_time} | "
        f"Live state: {STATE_FILE}"
    )
    
    
    # ============================================================
    # AUTO REFRESH
    # ============================================================
    
    time.sleep(2)
    
    st.rerun()    # ============================================================
    # AI CONFIDENCE
    # ============================================================

    st.markdown(
        '<div class="section-title">🧠 AI Confidence</div>',
        unsafe_allow_html=True
    )


    fig_confidence = go.Figure()

    fig_confidence.add_trace(
        go.Scatter(
            x=df["time"],
            y=df["confidence"],
            mode="lines+markers",
            name="Confidence",
            line=dict(width=4),
            marker=dict(size=7)
        )
    )

    fig_confidence.update_layout(
        title="AI Prediction Confidence Over Time",
        xaxis_title="Time",
        yaxis_title="Confidence (%)",
        yaxis=dict(
            range=[0, 100]
        ),
        height=380,
        margin=dict(l=50, r=30, t=60, b=50),
        hovermode="x unified"
    )

    st.plotly_chart(
        fig_confidence,
        use_container_width=True
    )


    # ============================================================
    # TRAFFIC MATRIX
    # ============================================================

    st.markdown(
        '<div class="section-title">🔢 AI Traffic Window</div>',
        unsafe_allow_html=True
    )

    matrix_shape = data.get(
        "matrix_shape",
        [20, 3]
    )

    m1, m2, m3 = st.columns(3)

    with m1:
        st.metric(
            "Window Rows",
            str(matrix_shape[0])
        )

    with m2:
        st.metric(
            "Features",
            str(matrix_shape[1])
        )

    with m3:
        st.metric(
            "AI Input",
            f"{matrix_shape[0]} × {matrix_shape[1]}"
        )


    st.info(
        "AI input features: Duration + Packet Count + Inter-arrival Time"
    )


    # ============================================================
    # LIVE UPDATE
    # ============================================================

    st.caption(
        f"Last update: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')} "
        f"| Monitoring conn.log through live_predictor.py"
    )


    # ============================================================
    # AUTO REFRESH
    # ============================================================




live_dashboard()
