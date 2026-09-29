import os
import time
import json
import numpy as np
import torch
import torch.nn as nn

# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "conn.log"
MODEL_FILE = "cyber_world_model.pt"
STATE_FILE = "live_state.json"

WINDOW_SIZE = 20

# Stage 2:
# Number of future states to forecast
K_STEPS = 5

CLASS_NAMES = [
    "Normal",
    "Port Scan",
    "Brute Force",
    "DoS",
    "Other"
]


# ============================================================
# MODEL DEFINITIONS
# ============================================================

class SpatialCompressor(nn.Module):
    """Compress network traffic features into latent states."""

    def __init__(self, in_features, latent_dim):

        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(in_features, 32),
            nn.ReLU(),
            nn.Linear(32, latent_dim),
            nn.ReLU()
        )

    def forward(self, x):

        return self.encoder(x)


class TemporalWorldModel(nn.Module):
    """Transformer-based temporal world model."""

    def __init__(self, latent_dim, num_classes):

        super().__init__()

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=latent_dim,
            nhead=2,
            dim_feedforward=64,
            batch_first=True
        )

        self.transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=1
        )

        self.future_state_head = nn.Linear(
            latent_dim,
            latent_dim
        )

        self.risk_head = nn.Linear(
            latent_dim,
            1
        )

        self.mitre_head = nn.Linear(
            latent_dim,
            num_classes
        )

    def forward(self, z_history):

        transformed = self.transformer(
            z_history
        )

        current_summary = transformed[:, -1, :]

        predicted_z_next = self.future_state_head(
            current_summary
        )

        risk_score = torch.sigmoid(
            self.risk_head(current_summary)
        )

        mitre_logits = self.mitre_head(
            current_summary
        )

        return (
            predicted_z_next,
            risk_score,
            mitre_logits
        )


# ============================================================
# LOAD MODEL
# ============================================================

if not os.path.exists(MODEL_FILE):

    raise FileNotFoundError(
        f"Model file not found: {MODEL_FILE}"
    )


checkpoint = torch.load(
    MODEL_FILE,
    map_location="cpu",
    weights_only=False
)


latent_dim = checkpoint["latent_dim"]
num_classes = checkpoint["num_classes"]
sequence_length = checkpoint["sequence_length"]

feature_names = checkpoint.get(
    "feature_names",
    [
        "duration_ms",
        "packet_count",
        "inter_arrival_ms"
    ]
)

mean = np.asarray(
    checkpoint["mean"],
    dtype=np.float32
)

std = np.asarray(
    checkpoint["std"],
    dtype=np.float32
)


compressor = SpatialCompressor(
    len(feature_names),
    latent_dim
)

world_model = TemporalWorldModel(
    latent_dim,
    num_classes
)


compressor.load_state_dict(
    checkpoint["compressor"]
)

world_model.load_state_dict(
    checkpoint["world_model"]
)


compressor.eval()
world_model.eval()


print()
print("==========================================")
print(" MODEL LOADED")
print("==========================================")
print(f"Classes         : {num_classes}")
print(f"Sequence Length : {sequence_length}")
print(f"Features        : {feature_names}")
print(f"Latent Dimension: {latent_dim}")
print(f"Forecast Steps  : {K_STEPS}")
print("==========================================")


# ============================================================
# TRAFFIC ENGINE
# ============================================================

class TrafficEngine:

    def __init__(self, window_size):

        self.window_size = window_size

        self.feature_window = []

        self.previous_timestamp = None


    def process_connection(self, data):

        timestamp = data["timestamp"]

        duration = data["duration"]

        orig_pkts = data["orig_pkts"]

        resp_pkts = data["resp_pkts"]


        # ----------------------------------------------------
        # Packet count
        # ----------------------------------------------------

        packet_count = (
            orig_pkts +
            resp_pkts
        )


        # ----------------------------------------------------
        # Inter-arrival time
        # ----------------------------------------------------

        if self.previous_timestamp is None:

            inter_arrival = 0.0

        else:

            inter_arrival = (
                timestamp -
                self.previous_timestamp
            ) * 1000.0


        self.previous_timestamp = timestamp


        # ----------------------------------------------------
        # Feature vector
        # ----------------------------------------------------

        feature_vector = [
            duration * 1000.0,
            packet_count,
            inter_arrival
        ]


        self.feature_window.append(
            feature_vector
        )


        # ----------------------------------------------------
        # Keep only latest WINDOW_SIZE states
        # ----------------------------------------------------

        if len(self.feature_window) > self.window_size:

            self.feature_window.pop(0)


        matrix = np.asarray(
            self.feature_window,
            dtype=np.float32
        )


        return {

            "timestamp": timestamp,

            "source_ip": data["source_ip"],

            "source_port": data["source_port"],

            "destination_ip":
                data["destination_ip"],

            "destination_port":
                data["destination_port"],

            "protocol": data["protocol"],

            "service": data["service"],

            "duration_ms":
                duration * 1000.0,

            "packet_count":
                packet_count,

            "inter_arrival_ms":
                inter_arrival,

            "matrix": matrix
        }


traffic_engine = TrafficEngine(
    WINDOW_SIZE
)


# ============================================================
# PARSE ZEEK CONNECTION
# ============================================================

def parse_conn_line(line):

    line = line.strip()

    if not line:

        return None


    # Skip Zeek comments

    if line.startswith("#"):

        return None


    fields = line.split("\t")


    if len(fields) < 20:

        return None


    try:

        timestamp = float(fields[0])

        source_ip = fields[2]

        source_port = fields[3]

        destination_ip = fields[4]

        destination_port = fields[5]

        protocol = fields[6]

        service = fields[7]

        duration = (
            0.0
            if fields[8] in ("-", "")
            else float(fields[8])
        )

        orig_bytes = (
            0
            if fields[9] in ("-", "")
            else int(float(fields[9]))
        )

        resp_bytes = (
            0
            if fields[10] in ("-", "")
            else int(float(fields[10]))
        )

        conn_state = fields[11]

        orig_pkts = (
            0
            if fields[16] in ("-", "")
            else int(float(fields[16]))
        )

        orig_ip_bytes = (
            0
            if fields[17] in ("-", "")
            else int(float(fields[17]))
        )

        resp_pkts = (
            0
            if fields[18] in ("-", "")
            else int(float(fields[18]))
        )

        resp_ip_bytes = (
            0
            if fields[19] in ("-", "")
            else int(float(fields[19]))
        )


        return {

            "timestamp": timestamp,

            "source_ip": source_ip,

            "source_port": source_port,

            "destination_ip":
                destination_ip,

            "destination_port":
                destination_port,

            "protocol": protocol,

            "service": service,

            "duration": duration,

            "orig_bytes": orig_bytes,

            "resp_bytes": resp_bytes,

            "conn_state": conn_state,

            "orig_pkts": orig_pkts,

            "orig_ip_bytes":
                orig_ip_bytes,

            "resp_pkts": resp_pkts,

            "resp_ip_bytes":
                resp_ip_bytes
        }


    except (ValueError, IndexError):

        return None


# ============================================================
# SAVE LIVE STATE
# ============================================================

def save_live_state(
    traffic,
    prediction=None
):

    state = {

        "timestamp":
            traffic["timestamp"],

        "source_ip":
            traffic["source_ip"],

        "source_port":
            traffic["source_port"],

        "destination_ip":
            traffic["destination_ip"],

        "destination_port":
            traffic["destination_port"],

        "protocol":
            traffic["protocol"],

        "service":
            traffic["service"],

        "duration_ms":
            traffic["duration_ms"],

        "packet_count":
            traffic["packet_count"],

        "inter_arrival_ms":
            traffic["inter_arrival_ms"],

        "matrix_shape":
            list(
                traffic["matrix"].shape
            ),

        "risk": None,

        "risk_percent": None,

        "class": None,

        "confidence": None,

        "confidence_percent": None,

        # Stage 2
        "forecast": [],

        # AI explainability
        "explanation": {}
    }


    if prediction is not None:

        risk = prediction["risk"]

        confidence = prediction[
            "confidence"
        ]


        state["risk"] = risk

        state["risk_percent"] = (
            risk * 100
        )

        state["class"] = (
            prediction["class"]
        )

        state["confidence"] = (
            confidence
        )

        state["confidence_percent"] = (
            confidence * 100
        )


        # ----------------------------------------------------
        # Stage 2 forecast
        # ----------------------------------------------------

        state["forecast"] = (
            prediction.get(
                "forecast",
                []
            )
        )

        state["explanation"] = (
            prediction.get(
                "explanation",
                {}
            )
        )


    # --------------------------------------------------------
    # Atomic write
    # --------------------------------------------------------

    temporary_file = (
        STATE_FILE + ".tmp"
    )


    with open(
        temporary_file,
        "w"
    ) as file:

        json.dump(
            state,
            file,
            indent=4
        )


    os.replace(
        temporary_file,
        STATE_FILE
    )


# ============================================================
# STAGE 2
# K-STEP FUTURE FORECAST
# ============================================================

def forecast_future(
    latent_sequence
):

    """
    Forecast future network states
    recursively in latent space.

    Input:
        latent_sequence
        Shape:
        [1, sequence_length, latent_dim]

    Output:
        List containing K future predictions.
    """


    forecast = []


    # --------------------------------------------------------
    # Copy the current latent history
    # --------------------------------------------------------

    history = latent_sequence.clone()


    # --------------------------------------------------------
    # Recursive K-step forecasting
    # --------------------------------------------------------

    with torch.no_grad():

        for step in range(
            1,
            K_STEPS + 1
        ):

            # -----------------------------------------------
            # Predict next state
            # -----------------------------------------------

            predicted_z_next, risk_score, mitre_logits = (
                world_model(history)
            )


            # -----------------------------------------------
            # Risk
            # -----------------------------------------------

            risk = float(
                risk_score.item()
            )


            # -----------------------------------------------
            # Class probabilities
            # -----------------------------------------------

            probabilities = torch.softmax(
                mitre_logits,
                dim=1
            )


            confidence, class_index = torch.max(
                probabilities,
                dim=1
            )


            confidence = float(
                confidence.item()
            )

            class_index = int(
                class_index.item()
            )


            # -----------------------------------------------
            # Class name
            # -----------------------------------------------

            if class_index < len(
                CLASS_NAMES
            ):

                class_name = (
                    CLASS_NAMES[
                        class_index
                    ]
                )

            else:

                class_name = "Other"


            # -----------------------------------------------
            # Store future prediction
            # -----------------------------------------------

            forecast.append({

                "step": step,

                "risk": risk,

                "risk_percent":
                    risk * 100,

                "class":
                    class_name,

                "confidence":
                    confidence,

                "confidence_percent":
                    confidence * 100
            })


            # -----------------------------------------------
            # IMPORTANT:
            # Use predicted latent state
            # as the next state.
            # -----------------------------------------------

            predicted_z_next = (
                predicted_z_next
                .unsqueeze(1)
            )


            # -----------------------------------------------
            # Remove oldest state
            # and append predicted state
            # -----------------------------------------------

            history = torch.cat(
                [
                    history[:, 1:, :],
                    predicted_z_next
                ],
                dim=1
            )


    return forecast


# ============================================================
# CURRENT PREDICTION + FUTURE FORECAST
# ============================================================

def predict(matrix):

    x = np.asarray(
        matrix,
        dtype=np.float32
    )


    # --------------------------------------------------------
    # Safety check
    # --------------------------------------------------------

    if x.shape[0] < sequence_length:

        raise ValueError(
            f"Need {sequence_length} "
            f"states, got {x.shape[0]}"
        )


    # --------------------------------------------------------
    # Use latest sequence
    # --------------------------------------------------------

    x = x[
        -sequence_length:
    ]


    # --------------------------------------------------------
    # Log transformation
    # --------------------------------------------------------

    x = np.log1p(
        np.maximum(x, 0)
    )


    # --------------------------------------------------------
    # Standardization
    # --------------------------------------------------------

    x = (
        x - mean
    ) / (
        std + 1e-8
    )


    # --------------------------------------------------------
    # Tensor
    #
    # Shape:
    # [1, sequence_length, features]
    # --------------------------------------------------------

    x_tensor = torch.tensor(
        x,
        dtype=torch.float32
    ).unsqueeze(0)


    # --------------------------------------------------------
    # Spatial compression
    # --------------------------------------------------------

    with torch.no_grad():

        latent_sequence = compressor(
            x_tensor
        )


        # ----------------------------------------------------
        # CURRENT AI PREDICTION
        # ----------------------------------------------------

        predicted_z_next, risk_score, mitre_logits = (
            world_model(
                latent_sequence
            )
        )


        # ----------------------------------------------------
        # Current risk
        # ----------------------------------------------------

        risk = float(
            risk_score.item()
        )


        # ----------------------------------------------------
        # Current class
        # ----------------------------------------------------

        probabilities = torch.softmax(
            mitre_logits,
            dim=1
        )


        confidence, class_index = torch.max(
            probabilities,
            dim=1
        )


        confidence = float(
            confidence.item()
        )

        class_index = int(
            class_index.item()
        )


    # --------------------------------------------------------
    # Current class name
    # --------------------------------------------------------

    if class_index < len(
        CLASS_NAMES
    ):

        class_name = (
            CLASS_NAMES[
                class_index
            ]
        )

    else:

        class_name = "Other"


    # ========================================================
    # AI EXPLANATION
    # ========================================================

    explanation = {}

    explanation_features = [
        "Connection Duration",
        "Packet Count",
        "Inter-arrival Time"
    ]

    with torch.no_grad():

        original_risk = risk

        for feature_index, feature_name in enumerate(
            explanation_features
        ):

            modified = x_tensor.clone()

            reference_value = torch.median(
                modified[:, :, feature_index]
            )

            modified[:, -1, feature_index] = (
                reference_value
            )

            modified_latent = compressor(
                modified
            )

            _, modified_risk, _ = world_model(
                modified_latent
            )

            modified_risk = float(
                modified_risk.item()
            )

            risk_change = abs(
                original_risk -
                modified_risk
            )

            explanation[feature_name] = {
                "risk_change": risk_change,
                "risk_change_percent":
                    risk_change * 100
            }

    total_contribution = sum(
        item["risk_change"]
        for item in explanation.values()
    )

    if total_contribution > 0:

        for item in explanation.values():

            item["contribution_percent"] = (
                item["risk_change"] /
                total_contribution
            ) * 100

    else:

        for item in explanation.values():

            item["contribution_percent"] = 0


    # ========================================================
    # STAGE 2 FORECAST
    # ========================================================

    forecast = forecast_future(
        latent_sequence
    )


    return {

        "risk": risk,

        "class": class_name,

        "confidence": confidence,

        "forecast": forecast,

        "explanation": explanation
    }


# ============================================================
# DISPLAY CONNECTION
# ============================================================

def print_connection(
    data,
    traffic
):

    print()

    print(
        "------------------------------------------"
    )

    print(
        "REAL-TIME NETWORK CONNECTION"
    )

    print(
        "------------------------------------------"
    )


    print(
        f"Timestamp        : "
        f"{data['timestamp']}"
    )

    print(
        f"Source IP        : "
        f"{data['source_ip']}"
    )

    print(
        f"Source Port      : "
        f"{data['source_port']}"
    )


    print(
        f"Destination IP   : "
        f"{data['destination_ip']}"
    )

    print(
        f"Destination Port : "
        f"{data['destination_port']}"
    )


    print(
        f"Protocol         : "
        f"{data['protocol']}"
    )

    print(
        f"Service          : "
        f"{data['service']}"
    )


    print(
        f"Duration         : "
        f"{traffic['duration_ms']:.3f} ms"
    )

    print(
        f"Packet Count     : "
        f"{traffic['packet_count']}"
    )


    print(
        f"Inter-arrival    : "
        f"{traffic['inter_arrival_ms']:.3f} ms"
    )


    print(
        f"Matrix Shape     : "
        f"{traffic['matrix'].shape}"
    )


# ============================================================
# DISPLAY FUTURE FORECAST
# ============================================================

def print_forecast(
    forecast
):

    print()

    print(
        "=========================================="
    )

    print(
        " 🔮 FUTURE ATTACK FORECAST"
    )

    print(
        "=========================================="
    )


    for item in forecast:

        print(
            f"+{item['step']} step"
            f"   | "
            f"Risk: "
            f"{item['risk_percent']:.2f}%"
            f" | "
            f"Class: "
            f"{item['class']}"
            f" | "
            f"Confidence: "
            f"{item['confidence_percent']:.2f}%"
        )


    print(
        "=========================================="
    )


# ============================================================
# MAIN LIVE LOOP
# ============================================================

def main():

    print()

    print(
        "=========================================="
    )

    print(
        " STARTING LIVE TRAFFIC MONITOR"
    )

    print(
        "=========================================="
    )

    print(
        f"Zeek log : {LOG_FILE}"
    )

    print(
        f"Window   : {WINDOW_SIZE}"
    )

    print(
        f"Forecast : {K_STEPS} future steps"
    )

    print()


    print(
        "Waiting for real-time Zeek connections..."
    )

    print(
        "Generate traffic using ping/curl "
        "in another terminal."
    )

    print(
        "Press Ctrl+C to stop."
    )


    print(
        "=========================================="
    )


    # --------------------------------------------------------
    # Check Zeek log
    # --------------------------------------------------------

    if not os.path.exists(
        LOG_FILE
    ):

        print()

        print(
            f"ERROR: {LOG_FILE} not found."
        )

        print()

        print(
            "Start Zeek first:"
        )

        print(
            "sudo /opt/zeek/bin/zeek "
            "-C -i eth0"
        )

        return


    # --------------------------------------------------------
    # Open Zeek log
    # --------------------------------------------------------

    with open(
        LOG_FILE,
        "r"
    ) as file:


        # Start at end of existing log

        file.seek(
            0,
            os.SEEK_END
        )


        while True:

            line = file.readline()


            # ------------------------------------------------
            # No new line
            # ------------------------------------------------

            if not line:

                time.sleep(
                    0.2
                )

                continue


            # ------------------------------------------------
            # Parse Zeek record
            # ------------------------------------------------

            data = parse_conn_line(
                line
            )


            if data is None:

                continue


            # ------------------------------------------------
            # Process connection
            # ------------------------------------------------

            traffic = (
                traffic_engine
                .process_connection(
                    data
                )
            )


            # ------------------------------------------------
            # Display connection
            # ------------------------------------------------

            print_connection(
                data,
                traffic
            )


            # ------------------------------------------------
            # Collect initial window
            # ------------------------------------------------

            if (
                traffic["matrix"].shape[0]
                < sequence_length
            ):

                print()

                print(
                    f"Collecting AI window: "
                    f"{traffic['matrix'].shape[0]}"
                    f"/{sequence_length}"
                )


                save_live_state(
                    traffic,
                    prediction=None
                )


                continue


            # =================================================
            # AI PREDICTION
            # =================================================

            prediction = predict(
                traffic["matrix"]
            )


            # ------------------------------------------------
            # Current prediction
            # ------------------------------------------------

            print()

            print(
                "=========================================="
            )

            print(
                " 🤖 AI PREDICTION"
            )

            print(
                "=========================================="
            )


            print(
                f"Risk       : "
                f"{prediction['risk'] * 100:.2f}%"
            )


            print(
                f"Class      : "
                f"{prediction['class']}"
            )


            print(
                f"Confidence : "
                f"{prediction['confidence'] * 100:.2f}%"
            )


            print(
                "=========================================="
            )


            # =================================================
            # STAGE 2 FORECAST DISPLAY
            # =================================================

            print_forecast(
                prediction["forecast"]
            )


            # ------------------------------------------------
            # Save prediction + forecast
            # ------------------------------------------------

            save_live_state(
                traffic,
                prediction
            )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    try:

        main()


    except KeyboardInterrupt:

        print()
        print()

        print(
            "=========================================="
        )

        print(
            " LIVE PREDICTOR STOPPED"
        )

        print(
            "=========================================="
        )


    except Exception as e:

        print()

        print(
            "=========================================="
        )

        print(
            " ERROR"
        )

        print(
            "=========================================="
        )

        print(e)

        print(
            "=========================================="
        )
