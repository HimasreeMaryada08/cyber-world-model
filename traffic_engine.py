from collections import deque
import numpy as np
import time


class TrafficEngine:

    def __init__(self, window_size=20):
        self.window_size = window_size
        self.window = deque(maxlen=window_size)

        # Python arrival time of the previous connection
        self.previous_arrival_time = None

    def process_connection(self, data):

        # -----------------------------------------
        # 1. Zeek connection timestamp
        # -----------------------------------------
        timestamp = float(data["timestamp"])

        # -----------------------------------------
        # 2. Duration
        # -----------------------------------------
        try:
            duration_ms = float(data["duration"]) * 1000
        except (ValueError, TypeError):
            duration_ms = 0.0

        # -----------------------------------------
        # 3. Packet counts
        # -----------------------------------------
        try:
            orig_pkts = int(data["orig_pkts"])
        except (ValueError, TypeError):
            orig_pkts = 0

        try:
            resp_pkts = int(data["resp_pkts"])
        except (ValueError, TypeError):
            resp_pkts = 0

        packet_count = orig_pkts + resp_pkts

        # -----------------------------------------
        # 4. REAL-TIME INTER-ARRIVAL TIME
        # -----------------------------------------
        current_arrival_time = time.time()

        if self.previous_arrival_time is None:
            inter_arrival_ms = 0.0
        else:
            inter_arrival_ms = (
                current_arrival_time -
                self.previous_arrival_time
            ) * 1000

        self.previous_arrival_time = current_arrival_time

        # -----------------------------------------
        # 5. Feature vector
        # -----------------------------------------
        features = [
            duration_ms,
            packet_count,
            inter_arrival_ms
        ]

        # -----------------------------------------
        # 6. Rolling window
        # -----------------------------------------
        self.window.append(features)

        matrix = np.array(
            self.window,
            dtype=np.float32
        )

        # -----------------------------------------
        # 7. Return processed result
        # -----------------------------------------
        return {
            "timestamp": timestamp,

            "source_ip": data["source_ip"],
            "destination_ip": data["destination_ip"],

            "source_port": data["source_port"],
            "destination_port": data["destination_port"],

            "protocol": data["protocol"],
            "service": data["service"],

            "duration_ms": duration_ms,
            "packet_count": packet_count,
            "inter_arrival_ms": inter_arrival_ms,

            "matrix": matrix
        }


# -----------------------------------------
# Standalone test
# -----------------------------------------

if __name__ == "__main__":

    engine = TrafficEngine(window_size=20)

    print("==========================================")
    print(" TRAFFIC ENGINE")
    print("==========================================")
    print("Rolling window size:", engine.window_size)
    print("Features:")
    print("  1. duration_ms")
    print("  2. packet_count")
    print("  3. inter_arrival_ms")
    print("==========================================")
