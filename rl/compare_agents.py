import sys
import os
import numpy as np
import json
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rl.hawkeye_env      import HawkEyeEnv
from rl.agents.dqn_agent import DQNAgent
from rl.agents.ppo_agent import PPOAgent
from rl.agents.a2c_agent import A2CAgent
from rl.trainer          import (
    train_random_baseline,
    train_greedy_baseline,
    evaluate_agent,
    save_results,
)
from rl.state_encoder import STATE_DIM, ACTION_DIM


def train_a2c(env, n_episodes: int = 200) -> A2CAgent:
    agent = A2CAgent(STATE_DIM, ACTION_DIM)
    for ep in range(n_episodes):
        agent.run_episode(env)
    return agent


def train_dqn(env, n_episodes: int = 200) -> DQNAgent:
    agent = DQNAgent(
        STATE_DIM, ACTION_DIM,
        batch_size=32, buffer_size=5000,
        epsilon_decay=0.99,
    )
    for ep in range(n_episodes):
        obs, info = env.reset()
        done = False
        while not done:
            mask   = info.get("action_mask")
            action = agent.select_action(obs, mask, training=True)
            next_obs, reward, term, trunc, info = env.step(action)
            agent.store_transition(obs, action, reward, next_obs, term or trunc)
            agent.update()
            obs = next_obs
            done = term or trunc
        agent.decay_epsilon()
    return agent


def train_ppo(env, n_updates: int = 50) -> PPOAgent:
    agent = PPOAgent(STATE_DIM, ACTION_DIM, rollout_len=64)
    for _ in range(n_updates):
        info = agent.collect_rollout(env)
        agent.update(info["last_value"])
    return agent


def run_full_comparison(
    n_eval:     int  = 50,
    verbose:    bool = True,
) -> dict:
    """
    Train all 3 agents + 2 baselines and compare.
    Returns full comparison results dict.
    """
    env = HawkEyeEnv(use_real_scan=False, max_steps=10)

    if verbose:
        print("\n" + "="*60)
        print("  HawkEye-RL Full Agent Comparison")
        print("="*60)

    results = {}

    # ── Baselines ──
    if verbose: print("\n[1/5] Running Random baseline...")
    results["random"] = train_random_baseline(env, n_eval)

    if verbose: print("[2/5] Running Greedy baseline...")
    results["greedy"] = train_greedy_baseline(env, n_eval)

    # ── A2C ──
    if verbose: print("[3/5] Training A2C (200 episodes)...")
    a2c = train_a2c(env, n_episodes=200)
    a2c.save("rl/models/a2c_hawkeye.pth")

    def a2c_policy(obs, info):
        a, _, _ = a2c.select_action(
            obs, info.get("action_mask"), training=False
        )
        return a

    results["a2c"] = evaluate_agent(env, a2c_policy, n_eval, "a2c")

    # ── DQN ──
    if verbose: print("[4/5] Training DQN (200 episodes)...")
    dqn = train_dqn(env, n_episodes=200)
    dqn.save("rl/models/dqn_hawkeye.pth")

    def dqn_policy(obs, info):
        return dqn.select_action(
            obs, info.get("action_mask"), training=False
        )

    results["dqn"] = evaluate_agent(env, dqn_policy, n_eval, "dqn")

    # ── PPO ──
    if verbose: print("[5/5] Training PPO (50 updates × 64 steps)...")
    ppo = train_ppo(env, n_updates=50)
    ppo.save("rl/models/ppo_hawkeye.pth")

    def ppo_policy(obs, info):
        a, _, _ = ppo.select_action(
            obs, info.get("action_mask"), training=False
        )
        return a

    results["ppo"] = evaluate_agent(env, ppo_policy, n_eval, "ppo")

    # ── Print comparison table ──
    if verbose:
        print("\n" + "="*60)
        print(f"  {'Agent':<10} {'Reward':>8} {'Findings':>10} {'Critical':>10} {'Steps':>8}")
        print("-"*60)
        for name in ["random", "greedy", "a2c", "dqn", "ppo"]:
            r = results[name]
            print(
                f"  {name:<10} "
                f"{r['mean_reward']:>+8.2f} "
                f"{r['mean_findings']:>10.1f} "
                f"{r.get('mean_critical', 0):>10.1f} "
                f"{r['mean_steps']:>8.1f}"
            )
        print("="*60)

        # Best agent
        best = max(
            ["a2c", "dqn", "ppo"],
            key=lambda k: results[k]["mean_reward"]
        )
        print(f"\n  Best RL agent: {best.upper()}")
        improvement = (
            (results[best]["mean_reward"] - results["greedy"]["mean_reward"])
            / max(abs(results["greedy"]["mean_reward"]), 0.1) * 100
        )
        print(f"  Improvement over greedy: {improvement:+.1f}%")

    # Save results
    save_results(
        results,
        f"comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    return results


if __name__ == "__main__":
    results = run_full_comparison(n_eval=50, verbose=True)