# model_engine.py

import torch
import torch.nn as nn


class SpatialCompressor(nn.Module):
    """Compresses tabular network relationship matrices into dynamic state representations."""

    def __init__(self, in_features, latent_dim):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(in_features, 32),
            nn.ReLU(),
            nn.Linear(32, latent_dim),
            nn.ReLU()
        )

    def forward(self, x):
        return self.encoder(x)  # Output Shape: [Batch, Latent_Dim]


class TemporalWorldModel(nn.Module):
    """Transformer-driven engine that learns network physics and projects future states."""

    def __init__(self, latent_dim, num_classes):
        super().__init__()

        # Positional Encoding Transformer mapping temporal trajectories
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

        # Predictive Forecast & Mapping Decoder Heads
        self.future_state_head = nn.Linear(latent_dim, latent_dim)
        self.risk_head = nn.Linear(latent_dim, 1)
        self.mitre_head = nn.Linear(latent_dim, num_classes)

    def forward(self, z_history):
        # z_history shape: [Batch, Sequence_Len, Latent_Dim]
        transformed = self.transformer(z_history)

        # Isolate the latest state window frame
        current_summary = transformed[:, -1, :]

        predicted_z_next = self.future_state_head(current_summary)

        risk_score = torch.sigmoid(
            self.risk_head(current_summary)
        )

        mitre_logits = self.mitre_head(current_summary)

        return predicted_z_next, risk_score, mitre_logits
