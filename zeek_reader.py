import os
import time

from traffic_engine import TrafficEngine


LOG_FILE = "conn.log"

engine = TrafficEngine(window_size=20)


def parse_connection(line, fields):
    values = line.rstrip("\n").split("\t")

    if len(values) < len(fields):
        return None

    try:
        data = {
            "timestamp": values[0],
            "source_ip": values[2],
            "source_port": values[3],
            "destination_ip": values[4],
            "destination_port": values[5],
            "protocol": values[6],
            "service": values[7],
            "duration": values[8],
            "orig_bytes": values[9],
            "resp_bytes": values[10],
            "conn_state": values[11],
            "orig_pkts": values[16],
            "resp_pkts": values[18],
        }

        return data

    except (IndexError, ValueError):
        return None


print("==========================================")
print(" ZEEK + TRAFFIC ENGINE REAL-TIME PIPELINE")
print("==========================================")
print("Monitoring:", LOG_FILE)
print("Rolling window: 20 connections")
print("Waiting for new connections...")
print()


fields = None

with open(LOG_FILE, "r") as file:

    # Read Zeek metadata/header first
    for line in file:

        if line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
            break

    # Move to end of file
    file.seek(0, os.SEEK_END)

    while True:

        line = file.readline()

        if not line:
            time.sleep(0.2)
            continue

        # Ignore metadata lines
        if line.startswith("#"):
            continue

        if fields is None:
            continue

        data = parse_connection(line, fields)

        if data is None:
            continue

        # Send connection to Traffic Engine
        result = engine.process_connection(data)

        print("------------------------------------------")
        print("NEW REAL-TIME CONNECTION")
        print("------------------------------------------")

        print("Source        :", result["source_ip"])
        print("Destination   :", result["destination_ip"])
        print("Protocol      :", result["protocol"])
        print("Service       :", result["service"])

        print("Duration (ms) :", round(result["duration_ms"], 3))
        print("Packets       :", result["packet_count"])
        print("Inter-arrival :", round(result["inter_arrival_ms"], 3), "ms")

        print()
        print("Rolling Matrix Shape:", result["matrix"].shape)
        print("Rolling Matrix:")
        print(result["matrix"])

        print("------------------------------------------")
