import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import random
import os
from collections import deque
from typing import List, Tuple, Optional

import os
if os.name == 'nt':  # Windows only
    anaconda_path = os.path.expanduser('~').replace('\\', '/').split('/')[0]
    dll_path = rf"C:\Users\{os.environ.get('USERNAME', 'user')}\anaconda3\Library\bin"
    if os.path.exists(dll_path):
        os.add_dll_directory(dll_path)
# ─────────────────────────────────────────
# NEURAL NETWORK
# ─────────────────────────────────────────

class DQNNetwork(nn.Module):
    """
    Deep Q-Network architecture.
    Input:  state vector (STATE_DIM)
    Output: Q-value for each action (ACTION_DIM)
    """

    def __init__(self, state_dim: int, action_dim: int,
                 hidden_dim: int = 128):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(state_dim,   hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim,  hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim,  hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, action_dim),
        )

        # Initialize weights
        for layer in self.network:
            if isinstance(layer, nn.Linear):
                nn.init.xavier_uniform_(layer.weight)
                nn.init.zeros_(layer.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


# ─────────────────────────────────────────
# REPLAY BUFFER
# ─────────────────────────────────────────

class ReplayBuffer:
    """
    Experience replay buffer.
    Stores (state, action, reward, next_state, done) transitions.
    """

    def __init__(self, capacity: int = 10000):
        self.buffer = deque(maxlen=capacity)

    def push(self, state: np.ndarray, action: int,
             reward: float, next_state: np.ndarray,
             done: bool):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int) -> Tuple:
        batch = random.sample(self.buffer, batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            np.array(states),
            np.array(actions),
            np.array(rewards, dtype=np.float32),
            np.array(next_states),
            np.array(dones, dtype=np.float32),
        )

    def __len__(self) -> int:
        return len(self.buffer)


# ─────────────────────────────────────────
# DQN AGENT
# ─────────────────────────────────────────

class DQNAgent:
    """
    Double DQN Agent with action masking.

    Improvements over vanilla DQN:
    - Double DQN: uses online network to select action,
      target network to evaluate — reduces overestimation
    - Action masking: invalid actions get -inf Q-value
    - Experience replay: breaks temporal correlations
    - Target network: stable training target
    """

    def __init__(
        self,
        state_dim:      int   = 40,
        action_dim:     int   = 9,
        hidden_dim:     int   = 128,
        lr:             float = 0.001,
        gamma:          float = 0.95,
        epsilon_start:  float = 1.0,
        epsilon_end:    float = 0.01,
        epsilon_decay:  float = 0.995,
        buffer_size:    int   = 10000,
        batch_size:     int   = 32,
        target_update:  int   = 100,
        device:         str   = "auto",
    ):
        self.state_dim     = state_dim
        self.action_dim    = action_dim
        self.gamma         = gamma
        self.epsilon       = epsilon_start
        self.epsilon_end   = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.batch_size    = batch_size
        self.target_update = target_update
        self.steps         = 0

        # Device
        if device == "auto":
            self.device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
        else:
            self.device = torch.device(device)

        # Networks
        self.online_net = DQNNetwork(
            state_dim, action_dim, hidden_dim
        ).to(self.device)
        self.target_net = DQNNetwork(
            state_dim, action_dim, hidden_dim
        ).to(self.device)
        self.target_net.load_state_dict(self.online_net.state_dict())
        self.target_net.eval()

        # Optimizer
        self.optimizer = optim.Adam(
            self.online_net.parameters(), lr=lr
        )

        # Replay buffer
        self.buffer = ReplayBuffer(buffer_size)

        # Training metrics
        self.losses       = []
        self.epsilons     = []
        self.q_values_log = []

    # ─────────────────────────────────────────
    # ACTION SELECTION
    # ─────────────────────────────────────────

    def select_action(
        self,
        state:       np.ndarray,
        action_mask: Optional[np.ndarray] = None,
        training:    bool = True,
    ) -> int:
        """
        Epsilon-greedy action selection with action masking.
        During training: explores randomly with prob epsilon.
        During eval: always picks best valid action.
        """
        # Exploration
        if training and random.random() < self.epsilon:
            if action_mask is not None:
                valid = np.where(action_mask)[0]
                return int(np.random.choice(valid))
            return self.action_dim - 1  # stop

        # Exploitation — pick highest Q-value valid action
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)

        with torch.no_grad():
            q_values = self.online_net(state_tensor).squeeze(0)

            # Apply action mask — set invalid actions to -inf
            if action_mask is not None:
                mask_tensor = torch.BoolTensor(action_mask).to(self.device)
                q_values    = q_values.masked_fill(~mask_tensor, float("-inf"))

            action = q_values.argmax().item()

        # Log Q-values periodically
        if self.steps % 100 == 0:
            self.q_values_log.append(
                q_values.cpu().numpy().tolist()
            )

        return int(action)

    # ─────────────────────────────────────────
    # LEARNING
    # ─────────────────────────────────────────

    def store_transition(
        self,
        state:      np.ndarray,
        action:     int,
        reward:     float,
        next_state: np.ndarray,
        done:       bool,
    ):
        """Store a transition in the replay buffer."""
        self.buffer.push(state, action, reward, next_state, done)

    def update(self) -> Optional[float]:
        """
        Sample a batch and perform one gradient update.
        Returns loss value or None if buffer too small.
        """
        if len(self.buffer) < self.batch_size:
            return None

        states, actions, rewards, next_states, dones = \
            self.buffer.sample(self.batch_size)

        # Convert to tensors
        states_t      = torch.FloatTensor(states).to(self.device)
        actions_t     = torch.LongTensor(actions).to(self.device)
        rewards_t     = torch.FloatTensor(rewards).to(self.device)
        next_states_t = torch.FloatTensor(next_states).to(self.device)
        dones_t       = torch.FloatTensor(dones).to(self.device)

        # Current Q-values
        current_q = self.online_net(states_t).gather(
            1, actions_t.unsqueeze(1)
        ).squeeze(1)

        # Double DQN target
        with torch.no_grad():
            # Online net selects action
            next_actions = self.online_net(next_states_t).argmax(1)
            # Target net evaluates it
            next_q       = self.target_net(next_states_t).gather(
                1, next_actions.unsqueeze(1)
            ).squeeze(1)
            target_q = rewards_t + self.gamma * next_q * (1 - dones_t)

        # Loss
        loss = nn.SmoothL1Loss()(current_q, target_q)

        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping for stability
        nn.utils.clip_grad_norm_(self.online_net.parameters(), 10.0)
        self.optimizer.step()

        loss_val = loss.item()
        self.losses.append(loss_val)
        return loss_val

    def decay_epsilon(self):
        """Decay exploration rate."""
        self.epsilon = max(
            self.epsilon_end,
            self.epsilon * self.epsilon_decay,
        )
        self.epsilons.append(self.epsilon)

    def update_target_network(self):
        """Copy online network weights to target network."""
        self.target_net.load_state_dict(
            self.online_net.state_dict()
        )

    # ─────────────────────────────────────────
    # SAVE / LOAD
    # ─────────────────────────────────────────

    def save(self, path: str):
        """Save model weights and training state."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            "online_net":    self.online_net.state_dict(),
            "target_net":    self.target_net.state_dict(),
            "optimizer":     self.optimizer.state_dict(),
            "epsilon":       self.epsilon,
            "steps":         self.steps,
            "losses":        self.losses[-100:],
        }, path)

    def load(self, path: str):
        """Load model weights."""
        checkpoint = torch.load(path, map_location=self.device)
        self.online_net.load_state_dict(checkpoint["online_net"])
        self.target_net.load_state_dict(checkpoint["target_net"])
        self.optimizer.load_state_dict(checkpoint["optimizer"])
        self.epsilon = checkpoint.get("epsilon", self.epsilon_end)
        self.steps   = checkpoint.get("steps",   0)

    def get_metrics(self) -> dict:
        """Return current training metrics."""
        return {
            "epsilon":    self.epsilon,
            "steps":      self.steps,
            "buffer_size":len(self.buffer),
            "mean_loss":  (
                float(np.mean(self.losses[-50:]))
                if self.losses else 0.0
            ),
        }