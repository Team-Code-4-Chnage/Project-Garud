"""
V2 network-state world model.

Encoder: 2-layer LSTM over a window of W network states.
Per rollout step k (1..H) the hidden state h_{k-1} of the window ending at
S[t+k-1] feeds three heads:
    next_state -> S_hat[t+k]
    risk       -> logit that state t+k contains malicious flows
    stage      -> stage logits for state t+k
The predicted state is appended to the window and the encoder is re-run, so
training (with scheduled teacher forcing) and inference use the same
recursive rollout.
"""
import torch
import torch.nn as nn


class NetStateWorldModel(nn.Module):
    def __init__(self, dim, hidden=256, layers=2, dropout=0.25, n_stages=6):
        super().__init__()
        self.lstm = nn.LSTM(dim, hidden, num_layers=layers, batch_first=True,
                            dropout=dropout if layers > 1 else 0.0)
        self.next_state = nn.Linear(hidden, dim)
        self.risk = nn.Sequential(nn.Linear(hidden, 64), nn.ReLU(), nn.Dropout(dropout), nn.Linear(64, 1))
        self.stage = nn.Sequential(nn.Linear(hidden, 64), nn.ReLU(), nn.Linear(64, n_stages))

    def step(self, w):
        _, (h, _) = self.lstm(w)
        h = h[-1]
        return self.next_state(h), self.risk(h).squeeze(-1), self.stage(h)

    def rollout(self, window, horizon, true_future=None, tf_prob=0.0):
        """window (B,W,D). Returns states (B,H,D), risk logits (B,H), stage logits (B,H,C).

        With true_future (B,H,D) and tf_prob>0, each sample independently feeds the
        true state instead of its own prediction (scheduled teacher forcing)."""
        w = window
        S, R, C = [], [], []
        for k in range(horizon):
            ns, r, c = self.step(w)
            S.append(ns)
            R.append(r)
            C.append(c)
            nxt = ns
            if true_future is not None and tf_prob > 0.0:
                use = (torch.rand(ns.shape[0], 1, device=ns.device) < tf_prob).float()
                nxt = use * true_future[:, k] + (1 - use) * ns
            w = torch.cat([w[:, 1:], nxt.unsqueeze(1)], dim=1)
        return torch.stack(S, 1), torch.stack(R, 1), torch.stack(C, 1)
