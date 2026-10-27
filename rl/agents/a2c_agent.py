import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Categorical
import os
from typing import Optional, Tuple

class A2CNetwork(nn.Module):
    """
    Shared network with actor and critic heads.
    Simpler than PPO — no clipping, synchronous updates.
    """

    def __init__(self, state_dim: int, action_dim: int,
                 hidden_dim: int = 128):
        super().__init__()

        self.base = nn.Sequential(
            nn.Linear(state_dim,  hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )
        self.actor  = nn.Linear(hidden_dim, action_dim)
        self.critic = nn.Linear(hidden_dim, 1)

        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=np.sqrt(2))
                nn.init.zeros_(m.bias)
        nn.init.orthogonal_(self.actor.weight, gain=0.01)

    def forward(self, x: torch.Tensor):
        f = self.base(x)
        return self.actor(f), self.critic(f)

    def get_action(self, x: torch.Tensor,
                   mask: Optional[torch.Tensor] = None,
                   greedy: bool = False):
        logits, value = self.forward(x)
        if mask is not None:
            logits = logits.masked_fill(~mask, -1e8)
        dist = Categorical(logits=logits)
        action = logits.argmax(-1) if greedy else dist.sample()
        return action, dist.log_prob(action), dist.entropy(), value.squeeze(-1)


class A2CAgent:
    """
    Advantage Actor-Critic — synchronous, no replay buffer.
    Fastest to train of the three algorithms.
    Used as comparison baseline against DQN and PPO.
    """

    def __init__(
        self,
        state_dim:     int   = 40,
        action_dim:    int   = 9,
        hidden_dim:    int   = 128,
        lr:            float = 7e-4,
        gamma:         float = 0.99,
        value_coef:    float = 0.25,
        entropy_coef:  float = 0.01,
        max_grad_norm: float = 0.5,
        n_steps:       int   = 5,
        device:        str   = "auto",
    ):
        self.gamma         = gamma
        self.value_coef    = value_coef
        self.entropy_coef  = entropy_coef
        self.max_grad_norm = max_grad_norm
        self.n_steps       = n_steps
        self.steps         = 0

        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        ) if device == "auto" else torch.device(device)

        self.network   = A2CNetwork(
            state_dim, action_dim, hidden_dim
        ).to(self.device)
        self.optimizer = optim.RMSprop(
            self.network.parameters(), lr=lr, eps=1e-5
        )

        self.policy_losses = []
        self.value_losses  = []
        self.entropies     = []

    def select_action(self, state: np.ndarray,
                      action_mask: Optional[np.ndarray] = None,
                      training: bool = True) -> Tuple[int, float, float]:
        s = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        m = (torch.BoolTensor(action_mask).unsqueeze(0).to(self.device)
             if action_mask is not None else None)
        with torch.no_grad():
            action, log_prob, _, value = self.network.get_action(
                s, m, greedy=not training
            )
        return int(action.item()), float(log_prob.item()), float(value.item())

    def update(self, transitions: list,
               last_value: float = 0.0) -> dict:
        """
        N-step A2C update.
        transitions = list of (state, action, reward, log_prob, value, done, mask)
        """
        if not transitions:
            return {"policy_loss": 0.0, "value_loss": 0.0, "entropy": 0.0}

        # Compute n-step returns
        returns = []
        R       = last_value
        for _, _, reward, _, _, done, _ in reversed(transitions):
            R = reward + self.gamma * R * (1 - float(done))
            returns.insert(0, R)

        states   = torch.FloatTensor(
            np.array([t[0] for t in transitions])
        ).to(self.device)
        actions  = torch.LongTensor(
            [t[1] for t in transitions]
        ).to(self.device)
        returns_t = torch.FloatTensor(returns).to(self.device)
        masks_t   = torch.BoolTensor(
            np.array([t[6] if t[6] is not None
                      else np.ones(9, dtype=bool)
                      for t in transitions])
        ).to(self.device)

        _, log_probs, entropy, values = self.network.get_action(
            states, masks_t
        )

        # Use actual actions taken
        logits, values_full = self.network(states)
        logits = logits.masked_fill(~masks_t, -1e8)
        dist   = Categorical(logits=logits)
        log_probs = dist.log_prob(actions)
        entropy   = dist.entropy()
        values    = values_full.squeeze(-1)

        advantages   = returns_t - values.detach()
        policy_loss  = -(log_probs * advantages).mean()
        value_loss   = nn.MSELoss()(values, returns_t)
        entropy_loss = -entropy.mean()

        loss = (policy_loss +
                self.value_coef   * value_loss +
                self.entropy_coef * entropy_loss)

        self.optimizer.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(
            self.network.parameters(), self.max_grad_norm
        )
        self.optimizer.step()
        self.steps += len(transitions)

        metrics = {
            "policy_loss": policy_loss.item(),
            "value_loss":  value_loss.item(),
            "entropy":     entropy.mean().item(),
        }
        self.policy_losses.append(metrics["policy_loss"])
        self.value_losses.append(metrics["value_loss"])
        self.entropies.append(metrics["entropy"])
        return metrics

    def run_episode(self, env) -> Tuple[float, int]:
        """Run one full episode with n-step updates."""
        obs, info  = env.reset()
        ep_reward  = 0.0
        done       = False
        transitions = []

        while not done:
            mask             = info.get("action_mask")
            action, lp, val  = self.select_action(obs, mask, training=True)
            next_obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            transitions.append((obs, action, reward, lp, val, done, mask))
            ep_reward += reward
            obs = next_obs

            # N-step update
            if len(transitions) >= self.n_steps or done:
                last_val = 0.0
                if not done:
                    _, _, last_val = self.select_action(
                        obs, info.get("action_mask"), training=False
                    )
                self.update(transitions, last_val)
                transitions = []

        summary = env.get_scan_summary()
        return ep_reward, summary["total_findings"]

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        torch.save({
            "network":   self.network.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "steps":     self.steps,
        }, path)

    def load(self, path: str):
        ckpt = torch.load(path, map_location=self.device)
        self.network.load_state_dict(ckpt["network"])
        self.optimizer.load_state_dict(ckpt["optimizer"])
        self.steps = ckpt.get("steps", 0)

    def get_metrics(self) -> dict:
        return {
            "steps":       self.steps,
            "policy_loss": float(np.mean(self.policy_losses[-10:])) if self.policy_losses else 0.0,
            "value_loss":  float(np.mean(self.value_losses[-10:]))  if self.value_losses  else 0.0,
            "entropy":     float(np.mean(self.entropies[-10:]))      if self.entropies      else 0.0,
        }