# Cyber World Model – Real-Time Network Traffic & AI Risk Monitoring

## Overview

Cyber World Model is an AI-based network security monitoring system that analyzes real-time network traffic and forecasts future security risks.

The system combines Zeek network monitoring with a temporal AI model to analyze network behavior, calculate threat risk, identify attack stages, and provide future risk forecasts through an interactive dashboard.

## System Architecture

Real Traffic
↓
Zeek
↓
Structured Network Flow Logs
↓
Feature Engineering
↓
Historical / Temporal Context
↓
AI Forecasting Model
↓
Threat Score
↓
Attack Classification
↓
Explainable Dashboard

## Technologies Used

- Python
- Zeek
- PyTorch
- Streamlit
- Pandas
- NumPy
- Plotly

## Main Components

- `traffic_engine.py` – Network traffic processing
- `zeek_reader.py` – Reads Zeek network logs
- `model_engine.py` – AI model and risk forecasting
- `live_predictor.py` – Live network risk prediction
- `dashboard.py` – Dashboard functionality
- `app.py` – Streamlit application
- `train.py` – Model training

## Project Goal

The goal of this project is to monitor evolving network behavior and forecast potential cyber security risks using temporal AI techniques.
