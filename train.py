import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim


# ============================================================
# CONFIGURATION
# ============================================================

SEQUENCE_LENGTH = 20
LATENT_DIM = 16
NUM_CLASSES = 5

EPOCHS = 30
LEARNING_RATE = 0.001

FEATURE_NAMES = [
    "duration_ms",
    "packet_count",
    "inter_arrival_ms"
]

CLASS_NAMES = [
    "Normal",
    "Port Scan",
    "Brute Force",
    "DoS",
    "Other"
]


# ============================================================
# SPATIAL COMPRESSOR
# ============================================================

class SpatialCompressor(nn.Module):

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


# ============================================================
# TEMPORAL WORLD MODEL
# ============================================================

class TemporalWorldModel(nn.Module):

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

        transformed = self.transformer(z_history)

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
# CREATE TRAINING DATA
# ============================================================

def create_training_data():

    np.random.seed(42)

    normal = []
    port_scan = []
    brute_force = []
    dos = []
    other = []

    # --------------------------------------------------------
    # NORMAL TRAFFIC
    # Class = 0
    # --------------------------------------------------------

    for _ in range(400):

        duration = np.random.uniform(10, 500)
        packets = np.random.randint(1, 30)
        inter_arrival = np.random.uniform(50, 5000)

        normal.append([
            duration,
            packets,
            inter_arrival,
            0,
            0.05
        ])

    # --------------------------------------------------------
    # PORT SCAN
    # Class = 1
    # --------------------------------------------------------

    for _ in range(200):

        duration = np.random.uniform(1, 100)
        packets = np.random.randint(1, 10)
        inter_arrival = np.random.uniform(0.1, 10)

        port_scan.append([
            duration,
            packets,
            inter_arrival,
            1,
            0.80
        ])

    # --------------------------------------------------------
    # BRUTE FORCE
    # Class = 2
    # --------------------------------------------------------

    for _ in range(200):

        duration = np.random.uniform(100, 2000)
        packets = np.random.randint(100, 2000)
        inter_arrival = np.random.uniform(5, 100)

        brute_force.append([
            duration,
            packets,
            inter_arrival,
            2,
            0.90
        ])

    # --------------------------------------------------------
    # DOS ATTACK
    # Class = 3
    # --------------------------------------------------------

    for _ in range(200):

        duration = np.random.uniform(1, 300)
        packets = np.random.randint(1000, 10000)
        inter_arrival = np.random.uniform(0.01, 5)

        dos.append([
            duration,
            packets,
            inter_arrival,
            3,
            0.95
        ])

    # --------------------------------------------------------
    # OTHER SUSPICIOUS TRAFFIC
    # Class = 4
    # --------------------------------------------------------

    for _ in range(200):

        duration = np.random.uniform(20, 1000)
        packets = np.random.randint(20, 500)
        inter_arrival = np.random.uniform(2, 200)

        other.append([
            duration,
            packets,
            inter_arrival,
            4,
            0.60
        ])

    # --------------------------------------------------------
    # COMBINE ALL CLASSES
    # --------------------------------------------------------

    data = np.array(
        normal
        + port_scan
        + brute_force
        + dos
        + other,
        dtype=np.float32
    )

    np.random.shuffle(data)

    return data


# ============================================================
# NORMALIZE FEATURES
# ============================================================

def normalize_features(data):

    features = data[:, :3]

    features = np.log1p(
        np.maximum(features, 0)
    )

    mean = features.mean(axis=0)

    std = features.std(axis=0)

    std = np.where(
        std < 1e-8,
        1.0,
        std
    )

    normalized = (
        features - mean
    ) / std

    return (
        normalized.astype(np.float32),
        mean.astype(np.float32),
        std.astype(np.float32)
    )


# ============================================================
# CREATE TEMPORAL SEQUENCES
# ============================================================

def create_sequences(
    features,
    labels,
    risks
):

    X = []
    Y = []
    risk_targets = []
    class_targets = []

    for i in range(
        len(features) - SEQUENCE_LENGTH
    ):

        X.append(
            features[
                i:i + SEQUENCE_LENGTH
            ]
        )

        Y.append(
            features[
                i + SEQUENCE_LENGTH
            ]
        )

        risk_targets.append(
            risks[
                i + SEQUENCE_LENGTH
            ]
        )

        class_targets.append(
            labels[
                i + SEQUENCE_LENGTH
            ]
        )

    return (
        np.array(X, dtype=np.float32),
        np.array(Y, dtype=np.float32),
        np.array(risk_targets, dtype=np.float32),
        np.array(class_targets, dtype=np.int64)
    )


# ============================================================
# TRAINING PIPELINE
# ============================================================

def run_training_pipeline():

    print()
    print("=" * 60)
    print("        CYBER WORLD MODEL TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # DATASET
    # --------------------------------------------------------

    raw_data = create_training_data()

    print()
    print("Training samples:", len(raw_data))

    # --------------------------------------------------------
    # VERIFY CLASS DISTRIBUTION
    # --------------------------------------------------------

    labels = raw_data[:, 3].astype(np.int64)

    print()
    print("Class distribution:")

    for class_id in range(NUM_CLASSES):

        count = np.sum(
            labels == class_id
        )

        print(
            f"  {class_id} - "
            f"{CLASS_NAMES[class_id]}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # NORMALIZATION
    # --------------------------------------------------------

    features, mean, std = normalize_features(
        raw_data
    )

    # --------------------------------------------------------
    # RISKS
    # --------------------------------------------------------

    risks = raw_data[:, 4].astype(
        np.float32
    )

    # --------------------------------------------------------
    # CREATE SEQUENCES
    # --------------------------------------------------------

    X, Y, risk_targets, class_targets = create_sequences(
        features,
        labels,
        risks
    )

    print()
    print("Sequence shape:", X.shape)
    print("Next-state shape:", Y.shape)
    print("Risk target shape:", risk_targets.shape)
    print("Class target shape:", class_targets.shape)

    # --------------------------------------------------------
    # CONVERT TO PYTORCH
    # --------------------------------------------------------

    X_tensor = torch.tensor(
        X,
        dtype=torch.float32
    )

    Y_tensor = torch.tensor(
        Y,
        dtype=torch.float32
    )

    risk_tensor = torch.tensor(
        risk_targets,
        dtype=torch.float32
    )

    class_tensor = torch.tensor(
        class_targets,
        dtype=torch.long
    )

    # --------------------------------------------------------
    # MODELS
    # --------------------------------------------------------

    compressor = SpatialCompressor(
        in_features=3,
        latent_dim=LATENT_DIM
    )

    world_model = TemporalWorldModel(
        latent_dim=LATENT_DIM,
        num_classes=NUM_CLASSES
    )

    # --------------------------------------------------------
    # OPTIMIZER
    # --------------------------------------------------------

    optimizer = optim.Adam(
        list(compressor.parameters())
        + list(world_model.parameters()),
        lr=LEARNING_RATE
    )

    # --------------------------------------------------------
    # LOSS FUNCTIONS
    # --------------------------------------------------------

    mse_loss = nn.MSELoss()
    ce_loss = nn.CrossEntropyLoss()
    bce_loss = nn.BCELoss()

    # --------------------------------------------------------
    # TRAINING
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("TRAINING STARTED")
    print("=" * 60)

    for epoch in range(
        1,
        EPOCHS + 1
    ):

        optimizer.zero_grad()

        # ----------------------------------------------------
        # COMPRESS EACH TIME STEP
        # ----------------------------------------------------

        z_history = []

        for t in range(SEQUENCE_LENGTH):

            z = compressor(
                X_tensor[:, t, :]
            )

            z_history.append(z)

        z_history = torch.stack(
            z_history,
            dim=1
        )

        # ----------------------------------------------------
        # WORLD MODEL
        # ----------------------------------------------------

        predicted_z, predicted_risk, mitre_logits = world_model(
            z_history
        )

        # ----------------------------------------------------
        # FUTURE STATE TARGET
        # ----------------------------------------------------

        target_z = compressor(
            Y_tensor
        )

        # ----------------------------------------------------
        # LOSSES
        # ----------------------------------------------------

        future_loss = mse_loss(
            predicted_z,
            target_z
        )

        risk_loss = bce_loss(
            predicted_risk.squeeze(1),
            risk_tensor
        )

        class_loss = ce_loss(
            mitre_logits,
            class_tensor
        )

        # ----------------------------------------------------
        # TOTAL LOSS
        # ----------------------------------------------------

        loss = (
            future_loss
            + risk_loss
            + class_loss
        )

        # ----------------------------------------------------
        # BACKPROPAGATION
        # ----------------------------------------------------

        loss.backward()

        optimizer.step()

        # ----------------------------------------------------
        # PRINT PROGRESS
        # ----------------------------------------------------

        print(
            f"Epoch [{epoch:02d}/{EPOCHS}] | "
            f"Loss: {loss.item():.4f} | "
            f"Future: {future_loss.item():.4f} | "
            f"Risk: {risk_loss.item():.4f} | "
            f"Class: {class_loss.item():.4f}"
        )

    # ========================================================
    # SAVE CHECKPOINT
    # ========================================================

    checkpoint = {
        "compressor":
            compressor.state_dict(),

        "world_model":
            world_model.state_dict(),

        "latent_dim":
            LATENT_DIM,

        "num_classes":
            NUM_CLASSES,

        "sequence_length":
            SEQUENCE_LENGTH,

        "feature_names":
            FEATURE_NAMES,

        "mean":
            mean,

        "std":
            std
    }

    torch.save(
        checkpoint,
        "cyber_world_model.pt"
    )

    # ========================================================
    # COMPLETION
    # ========================================================

    print()
    print("=" * 60)
    print("✓ TRAINING COMPLETED")
    print("✓ MODEL CHECKPOINT SAVED")
    print("  File: cyber_world_model.pt")
    print()
    print("Classes trained:")

    for i, name in enumerate(CLASS_NAMES):

        print(
            f"  {i} → {name}"
        )

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run_training_pipeline()
