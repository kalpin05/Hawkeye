import numpy as np
import os
import sys
import json
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def train_random_baseline(env, n_episodes: int = 100) -> dict:
    """
    Train a random agent as baseline.
    Picks random valid action each step.
    """
    rewards   = []
    findings  = []
    steps     = []

    for ep in range(n_episodes):
        obs, info = env.reset()
        ep_reward = 0
        done      = False

        while not done:
            # Random valid action
            mask           = info.get("action_mask",
                                      np.ones(env.action_space.n, dtype=bool))
            valid_actions  = np.where(mask)[0]
            action         = np.random.choice(valid_actions)
            obs, reward, terminated, truncated, info = env.step(action)
            ep_reward += reward
            done       = terminated or truncated

        summary = env.get_scan_summary()
        rewards.append(ep_reward)
        findings.append(summary["total_findings"])
        steps.append(summary["steps_taken"])

    return {
        "agent":          "random",
        "mean_reward":    float(np.mean(rewards)),
        "std_reward":     float(np.std(rewards)),
        "mean_findings":  float(np.mean(findings)),
        "mean_steps":     float(np.mean(steps)),
        "rewards":        rewards,
    }


def train_greedy_baseline(env, n_episodes: int = 100) -> dict:
    """
    Train a greedy agent as baseline.
    Always runs the next unrun module in fixed order.
    """
    MODULE_ORDER = [
        0,  # headers
        5,  # recon
        4,  # api
        3,  # web
        1,  # network fast
        6,  # subdomains
        7,  # logic
        8,  # stop
    ]

    rewards  = []
    findings = []
    steps    = []

    for ep in range(n_episodes):
        obs, info = env.reset()
        ep_reward = 0
        done      = False
        mod_idx   = 0

        while not done:
            mask = info.get("action_mask",
                            np.ones(env.action_space.n, dtype=bool))

            # Pick next valid action in order
            action = 8  # default stop
            for i in range(mod_idx, len(MODULE_ORDER)):
                candidate = MODULE_ORDER[i]
                if mask[candidate]:
                    action  = candidate
                    mod_idx = i + 1
                    break

            obs, reward, terminated, truncated, info = env.step(action)
            ep_reward += reward
            done       = terminated or truncated

        summary = env.get_scan_summary()
        rewards.append(ep_reward)
        findings.append(summary["total_findings"])
        steps.append(summary["steps_taken"])

    return {
        "agent":         "greedy",
        "mean_reward":   float(np.mean(rewards)),
        "std_reward":    float(np.std(rewards)),
        "mean_findings": float(np.mean(findings)),
        "mean_steps":    float(np.mean(steps)),
        "rewards":       rewards,
    }


def save_results(results: dict, filename: str):
    """Save training results to JSON."""
    results_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "results"
    )
    os.makedirs(results_dir, exist_ok=True)
    path = os.path.join(results_dir, filename)
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {path}")
    return path


def evaluate_agent(env, policy_fn, n_episodes: int = 50,
                   agent_name: str = "agent") -> dict:
    """
    Evaluate any agent given a policy function.
    policy_fn(obs, info) -> action
    """
    rewards  = []
    findings = []
    steps    = []
    critical = []
    high     = []

    for ep in range(n_episodes):
        obs, info = env.reset()
        ep_reward = 0
        done      = False

        while not done:
            action = policy_fn(obs, info)
            obs, reward, terminated, truncated, info = env.step(action)
            ep_reward += reward
            done = terminated or truncated

        summary = env.get_scan_summary()
        rewards.append(ep_reward)
        findings.append(summary["total_findings"])
        steps.append(summary["steps_taken"])
        critical.append(summary["severity_counts"].get("critical", 0))
        high.append(summary["severity_counts"].get("high", 0))

    return {
        "agent":          agent_name,
        "mean_reward":    float(np.mean(rewards)),
        "std_reward":     float(np.std(rewards)),
        "mean_findings":  float(np.mean(findings)),
        "mean_steps":     float(np.mean(steps)),
        "mean_critical":  float(np.mean(critical)),
        "mean_high":      float(np.mean(high)),
        "rewards":        rewards,
    }