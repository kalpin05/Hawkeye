import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Categorical
import os
from typing import Optional, List, Tuple

# ─────────────────────────────────────────
# ACTOR-CRITIC NETWORK
# ─────────────────────────────────────────

class ActorCritic(nn.Module):
    """
    Shared base network with separate Actor and Critic heads.
    Actor:  outputs action probabilities
    Critic: outputs state value estimate
    """

    def __init__(self, state_dim: int, action_dim: int,
                 hidden_dim: int = 128):
        super().__init__()

        # Shared feature extractor
        self.base = nn.Sequential(
            nn.Linear(state_dim,  hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
        )

        # Actor head — outputs logits
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, action_dim),
        )

        # Critic head — outputs scalar value
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1),
        )

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.orthogonal_(module.weight, gain=np.sqrt(2))
                nn.init.zeros_(module.bias)
        # Smaller init for actor output
        nn.init.orthogonal_(self.actor[-1].weight, gain=0.01)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        features = self.base(x)
        logits   = self.actor(features)
        value    = self.critic(features)
        return logits, value

    def get_action_and_value(
        self,
        x:           torch.Tensor,
        action_mask: Optional[torch.Tensor] = None,
        action:      Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Get action, log_prob, entropy, value for PPO update.
        Applies action masking before sampling.
        """
        logits, value = self.forward(x)

        # Apply action mask — set invalid to large negative
        if action_mask is not None:
            logits = logits.masked_fill(~action_mask, -1e8)

        dist    = Categorical(logits=logits)
        if action is None:
            action = dist.sample()

        log_prob = dist.log_prob(action)
        entropy  = dist.entropy()

        return action, log_prob, entropy, value.squeeze(-1)


# ─────────────────────────────────────────
# ROLLOUT BUFFER
# ─────────────────────────────────────────

class RolloutBuffer:
    """
    Stores one rollout of experience for PPO update.
    PPO collects N steps then updates — no replay needed.
    """

    def __init__(self, rollout_len: int, state_dim: int,
                 action_dim: int, device: torch.device):
        self.rollout_len = rollout_len
        self.device      = device
        self.reset()

    def reset(self):
        self.states      = []
        self.actions     = []
        self.log_probs   = []
        self.rewards     = []
        self.values      = []
        self.dones       = []
        self.masks       = []
        self.ptr         = 0

    def push(self, state, action, log_prob, reward,
             value, done, mask=None):
        self.states.append(state)
        self.actions.append(action)
        self.log_probs.append(log_prob)
        self.rewards.append(reward)
        self.values.append(value)
        self.dones.append(done)
        self.masks.append(
            mask if mask is not None
            else np.ones(9, dtype=bool)
        )
        self.ptr += 1

    def is_full(self) -> bool:
        return self.ptr >= self.rollout_len

    def compute_returns(self, last_value: float,
                        gamma: float = 0.99,
                        gae_lambda: float = 0.95) -> np.ndarray:
        """Compute GAE (Generalized Advantage Estimation) returns."""
        rewards  = np.array(self.rewards,  dtype=np.float32)
        values   = np.array(self.values,   dtype=np.float32)
        dones    = np.array(self.dones,    dtype=np.float32)

        advantages = np.zeros_like(rewards)
        last_gae   = 0.0

        for t in reversed(range(len(rewards))):
            if t == len(rewards) - 1:
                next_val = last_value
                next_done = 0.0
            else:
                next_val  = values[t + 1]
                next_done = dones[t + 1]

            delta       = (rewards[t] + gamma * next_val *
                          (1 - next_done) - values[t])
            last_gae    = (delta + gamma * gae_lambda *
                          (1 - next_done) * last_gae)
            advantages[t] = last_gae

        returns = advantages + values
        return advantages, returns

    def get_batches(self, batch_size: int,
                    advantages: np.ndarray,
                    returns:    np.ndarray):
        """Yield mini-batches for PPO update epochs."""
        n       = len(self.states)
        indices = np.random.permutation(n)

        states   = torch.FloatTensor(
            np.array(self.states)).to(self.device)
        actions  = torch.LongTensor(
            np.array(self.actions)).to(self.device)
        log_probs = torch.FloatTensor(
            np.array([lp.item() if hasattr(lp, 'item')
                      else float(lp)
                      for lp in self.log_probs])).to(self.device)
        advs     = torch.FloatTensor(advantages).to(self.device)
        rets     = torch.FloatTensor(returns).to(self.device)
        masks    = torch.BoolTensor(
            np.array(self.masks)).to(self.device)

        # Normalize advantages
        advs = (advs - advs.mean()) / (advs.std() + 1e-8)

        for start in range(0, n, batch_size):
            idx = indices[start:start + batch_size]
            yield (states[idx], actions[idx], log_probs[idx],
                   advs[idx], rets[idx], masks[idx])


# ─────────────────────────────────────────
# PPO AGENT
# ─────────────────────────────────────────

class PPOAgent:
    """
    Proximal Policy Optimization agent with:
    - Clipped surrogate objective
    - GAE advantage estimation
    - Action masking
    - Entropy bonus for exploration
    - Value function clipping
    """

    def __init__(
        self,
        state_dim:        int   = 40,
        action_dim:       int   = 9,
        hidden_dim:       int   = 128,
        lr:               float = 3e-4,
        gamma:            float = 0.99,
        gae_lambda:       float = 0.95,
        clip_epsilon:     float = 0.2,
        value_coef:       float = 0.5,
        entropy_coef:     float = 0.01,
        max_grad_norm:    float = 0.5,
        rollout_len:      int   = 128,
        batch_size:       int   = 64,
        update_epochs:    int   = 4,
        device:           str   = "auto",
    ):
        self.gamma         = gamma
        self.gae_lambda    = gae_lambda
        self.clip_epsilon  = clip_epsilon
        self.value_coef    = value_coef
        self.entropy_coef  = entropy_coef
        self.max_grad_norm = max_grad_norm
        self.rollout_len   = rollout_len
        self.batch_size    = batch_size
        self.update_epochs = update_epochs
        self.steps         = 0

        if device == "auto":
            self.device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
        else:
            self.device = torch.device(device)

        # Network
        self.network = ActorCritic(
            state_dim, action_dim, hidden_dim
        ).to(self.device)

        # Optimizer
        self.optimizer = optim.Adam(
            self.network.parameters(), lr=lr, eps=1e-5
        )

        # Rollout buffer
        self.buffer = RolloutBuffer(
            rollout_len, state_dim, action_dim, self.device
        )

        # Metrics
        self.policy_losses  = []
        self.value_losses   = []
        self.entropy_losses = []
        self.total_losses   = []

    # ─────────────────────────────────────────
    # ACTION SELECTION
    # ─────────────────────────────────────────

    def select_action(
        self,
        state:       np.ndarray,
        action_mask: Optional[np.ndarray] = None,
        training:    bool = True,
    ) -> Tuple[int, float, float]:
        """
        Select action using current policy.
        Returns (action, log_prob, value)
        """
        state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)

        mask_t = None
        if action_mask is not None:
            mask_t = torch.BoolTensor(action_mask).unsqueeze(0).to(self.device)

        with torch.no_grad():
            if training:
                action, log_prob, _, value = \
                    self.network.get_action_and_value(state_t, mask_t)
            else:
                # Greedy during eval
                logits, value = self.network(state_t)
                if mask_t is not None:
                    logits = logits.masked_fill(~mask_t, -1e8)
                action   = logits.argmax(dim=-1)
                dist     = Categorical(logits=logits)
                log_prob = dist.log_prob(action)

        return (
            int(action.item()),
            float(log_prob.item()),
            float(value.item()),
        )

    # ─────────────────────────────────────────
    # COLLECT EXPERIENCE
    # ─────────────────────────────────────────

    def collect_rollout(self, env) -> dict:
        """Collect one full rollout of experience."""
        self.buffer.reset()
        obs, info = env.reset()
        ep_rewards   = []
        ep_findings  = []
        current_ep_r = 0.0

        while not self.buffer.is_full():
            mask             = info.get("action_mask")
            action, log_prob, value = self.select_action(
                obs, mask, training=True
            )

            next_obs, reward, terminated, truncated, info = \
                env.step(action)
            done = terminated or truncated

            self.buffer.push(
                obs, action, log_prob, reward,
                value, done, mask
            )

            current_ep_r += reward
            obs           = next_obs
            self.steps   += 1

            if done:
                ep_rewards.append(current_ep_r)
                summary = env.get_scan_summary()
                ep_findings.append(summary["total_findings"])
                current_ep_r = 0.0
                obs, info = env.reset()

        # Get value of last state for GAE
        with torch.no_grad():
            _, last_value = self.network(
                torch.FloatTensor(obs).unsqueeze(0).to(self.device)
            )
        last_value = float(last_value.item())

        return {
            "mean_reward":   float(np.mean(ep_rewards))  if ep_rewards  else 0.0,
            "mean_findings": float(np.mean(ep_findings)) if ep_findings else 0.0,
            "n_episodes":    len(ep_rewards),
            "last_value":    last_value,
        }

    # ─────────────────────────────────────────
    # PPO UPDATE
    # ─────────────────────────────────────────

    def update(self, last_value: float) -> dict:
        """
        Perform PPO update using collected rollout.
        Returns dict of loss metrics.
        """
        advantages, returns = self.buffer.compute_returns(
            last_value, self.gamma, self.gae_lambda
        )

        total_policy_loss  = 0.0
        total_value_loss   = 0.0
        total_entropy      = 0.0
        n_updates          = 0

        for epoch in range(self.update_epochs):
            for batch in self.buffer.get_batches(
                self.batch_size, advantages, returns
            ):
                states, actions, old_log_probs, advs, rets, masks = batch

                # Forward pass
                _, new_log_probs, entropy, values = \
                    self.network.get_action_and_value(
                        states, masks, actions
                    )

                # Policy loss (clipped surrogate)
                ratio        = (new_log_probs - old_log_probs).exp()
                surr1        = ratio * advs
                surr2        = torch.clamp(
                    ratio,
                    1 - self.clip_epsilon,
                    1 + self.clip_epsilon,
                ) * advs
                policy_loss  = -torch.min(surr1, surr2).mean()

                # Value loss
                value_loss   = nn.MSELoss()(values, rets)

                # Entropy bonus
                entropy_loss = -entropy.mean()

                # Total loss
                loss = (policy_loss +
                        self.value_coef    * value_loss +
                        self.entropy_coef  * entropy_loss)

                self.optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(
                    self.network.parameters(),
                    self.max_grad_norm
                )
                self.optimizer.step()

                total_policy_loss += policy_loss.item()
                total_value_loss  += value_loss.item()
                total_entropy     += entropy.mean().item()
                n_updates         += 1

        metrics = {
            "policy_loss":  total_policy_loss  / max(n_updates, 1),
            "value_loss":   total_value_loss   / max(n_updates, 1),
            "entropy":      total_entropy       / max(n_updates, 1),
        }

        self.policy_losses.append(metrics["policy_loss"])
        self.value_losses.append(metrics["value_loss"])
        self.entropy_losses.append(metrics["entropy"])

        return metrics

    # ─────────────────────────────────────────
    # SAVE / LOAD
    # ─────────────────────────────────────────

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
            "steps":         self.steps,
            "policy_loss":   (float(np.mean(self.policy_losses[-10:]))
                              if self.policy_losses else 0.0),
            "value_loss":    (float(np.mean(self.value_losses[-10:]))
                              if self.value_losses else 0.0),
            "entropy":       (float(np.mean(self.entropy_losses[-10:]))
                              if self.entropy_losses else 0.0),
        }