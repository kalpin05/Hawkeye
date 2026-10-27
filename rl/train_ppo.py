import sys
import os
import numpy as np
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rl.hawkeye_env       import HawkEyeEnv
from rl.agents.ppo_agent  import PPOAgent
from rl.trainer           import (
    train_random_baseline,
    train_greedy_baseline,
    evaluate_agent,
    save_results,
)
from rl.state_encoder import STATE_DIM, ACTION_DIM


def train_ppo(
    n_updates:   int  = 100,
    rollout_len: int  = 128,
    max_steps:   int  = 10,
    save_path:   str  = "rl/models/ppo_hawkeye.pth",
    verbose:     bool = True,
) -> dict:
    """
    Train PPO agent on HawkEye environment.
    PPO collects rollout_len steps then updates — no episode loop needed.
    """
    env   = HawkEyeEnv(use_real_scan=False, max_steps=max_steps)
    agent = PPOAgent(
        state_dim     = STATE_DIM,
        action_dim    = ACTION_DIM,
        hidden_dim    = 128,
        lr            = 3e-4,
        gamma         = 0.99,
        gae_lambda    = 0.95,
        clip_epsilon  = 0.2,
        value_coef    = 0.5,
        entropy_coef  = 0.01,
        rollout_len   = rollout_len,
        batch_size    = 64,
        update_epochs = 4,
    )

    history = {
        "update_rewards":  [],
        "update_findings": [],
        "policy_losses":   [],
        "value_losses":    [],
        "entropies":       [],
        "eval_rewards":    [],
        "eval_findings":   [],
    }

    best_eval_reward = float("-inf")

    if verbose:
        print(f"\n{'='*55}")
        print(f"  Training PPO Agent — {n_updates} updates")
        print(f"  Rollout length: {rollout_len} steps/update")
        print(f"  Device: {agent.device}")
        print(f"{'='*55}\n")

    for update in range(n_updates):
        # Collect rollout
        rollout_info = agent.collect_rollout(env)

        # PPO update
        metrics = agent.update(rollout_info["last_value"])

        # Log
        history["update_rewards"].append(rollout_info["mean_reward"])
        history["update_findings"].append(rollout_info["mean_findings"])
        history["policy_losses"].append(metrics["policy_loss"])
        history["value_losses"].append(metrics["value_loss"])
        history["entropies"].append(metrics["entropy"])

        # Print progress
        if verbose and (update + 1) % 10 == 0:
            recent_r = np.mean(history["update_rewards"][-10:])
            recent_f = np.mean(history["update_findings"][-10:])
            print(
                f"  Update {update+1:>4}/{n_updates} | "
                f"Reward: {recent_r:+6.2f} | "
                f"Findings: {recent_f:4.1f} | "
                f"Policy Loss: {metrics['policy_loss']:6.4f} | "
                f"Entropy: {metrics['entropy']:5.3f}"
            )

        # Evaluate every 20 updates
        if (update + 1) % 20 == 0:
            def ppo_policy(obs, info):
                action, _, _ = agent.select_action(
                    obs, info.get("action_mask"), training=False
                )
                return action

            eval_r = evaluate_agent(env, ppo_policy, 20, "ppo")
            history["eval_rewards"].append(eval_r["mean_reward"])
            history["eval_findings"].append(eval_r["mean_findings"])

            if eval_r["mean_reward"] > best_eval_reward:
                best_eval_reward = eval_r["mean_reward"]
                agent.save(save_path)
                if verbose:
                    print(f"  ✓ Best model saved (reward: {best_eval_reward:+.2f})")

    # Final comparison
    if verbose:
        print(f"\n{'='*55}")
        print("  Final Evaluation vs Baselines")
        print(f"{'='*55}")

    def ppo_policy(obs, info):
        action, _, _ = agent.select_action(
            obs, info.get("action_mask"), training=False
        )
        return action

    ppo_eval  = evaluate_agent(env, ppo_policy,       50, "ppo")
    rand_eval = train_random_baseline(env,  n_episodes=50)
    grdy_eval = train_greedy_baseline(env,  n_episodes=50)

    if verbose:
        print(f"  Random: reward={rand_eval['mean_reward']:+.2f}  findings={rand_eval['mean_findings']:.1f}")
        print(f"  Greedy: reward={grdy_eval['mean_reward']:+.2f}  findings={grdy_eval['mean_findings']:.1f}")
        print(f"  PPO:    reward={ppo_eval['mean_reward']:+.2f}  findings={ppo_eval['mean_findings']:.1f}")

        improvement = (
            (ppo_eval["mean_reward"] - grdy_eval["mean_reward"])
            / max(abs(grdy_eval["mean_reward"]), 0.1) * 100
        )
        print(f"\n  PPO improvement over greedy: {improvement:+.1f}%")

    history["final_eval"] = {
        "ppo":    ppo_eval,
        "random": rand_eval,
        "greedy": grdy_eval,
    }

    save_results(
        history,
        f"ppo_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    return history, agent


if __name__ == "__main__":
    history, agent = train_ppo(n_updates=100, verbose=True)
    print("\nPPO training complete!")