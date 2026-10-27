import sys
import os
import numpy as np
import json
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rl.hawkeye_env  import HawkEyeEnv
from rl.agents.dqn_agent import DQNAgent
from rl.trainer      import (
    train_random_baseline,
    train_greedy_baseline,
    evaluate_agent,
    save_results,
)
from rl.state_encoder import STATE_DIM, ACTION_DIM


def train_dqn(
    n_episodes:     int   = 500,
    max_steps:      int   = 10,
    eval_every:     int   = 50,
    save_path:      str   = "rl/models/dqn_hawkeye.pth",
    verbose:        bool  = True,
) -> dict:
    """
    Train DQN agent on HawkEye environment.
    Returns training history dict.
    """
    env   = HawkEyeEnv(use_real_scan=False, max_steps=max_steps)
    agent = DQNAgent(
        state_dim      = STATE_DIM,
        action_dim     = ACTION_DIM,
        hidden_dim     = 128,
        lr             = 0.001,
        gamma          = 0.95,
        epsilon_start  = 1.0,
        epsilon_end    = 0.01,
        epsilon_decay  = 0.995,
        buffer_size    = 10000,
        batch_size     = 32,
        target_update  = 100,
    )

    history = {
        "episode_rewards":  [],
        "episode_findings": [],
        "episode_steps":    [],
        "eval_rewards":     [],
        "eval_findings":    [],
        "losses":           [],
        "epsilons":         [],
    }

    best_eval_reward = float("-inf")

    if verbose:
        print(f"\n{'='*55}")
        print(f"  Training DQN Agent — {n_episodes} episodes")
        print(f"  Device: {agent.device}")
        print(f"{'='*55}\n")

    for episode in range(n_episodes):
        obs, info = env.reset()
        ep_reward = 0.0
        done      = False

        while not done:
            # Select action
            action_mask = info.get("action_mask")
            action      = agent.select_action(
                obs, action_mask, training=True
            )

            # Step environment
            next_obs, reward, terminated, truncated, next_info = \
                env.step(action)
            done = terminated or truncated

            # Store transition
            agent.store_transition(
                obs, action, reward, next_obs, done
            )

            # Learn
            loss = agent.update()
            if loss is not None:
                history["losses"].append(loss)

            # Update target network
            agent.steps += 1
            if agent.steps % agent.target_update == 0:
                agent.update_target_network()

            obs    = next_obs
            info   = next_info
            ep_reward += reward

        # Decay exploration
        agent.decay_epsilon()
        history["epsilons"].append(agent.epsilon)

        # Log episode
        summary = env.get_scan_summary()
        history["episode_rewards"].append(ep_reward)
        history["episode_findings"].append(summary["total_findings"])
        history["episode_steps"].append(summary["steps_taken"])

        # Print progress
        if verbose and (episode + 1) % 50 == 0:
            recent_rewards  = history["episode_rewards"][-50:]
            recent_findings = history["episode_findings"][-50:]
            print(
                f"  Episode {episode+1:>4}/{n_episodes} | "
                f"Reward: {np.mean(recent_rewards):+6.2f} | "
                f"Findings: {np.mean(recent_findings):4.1f} | "
                f"Epsilon: {agent.epsilon:.3f} | "
                f"Loss: {np.mean(history['losses'][-50:]) if history['losses'] else 0:.4f}"
            )

        # Evaluate periodically
        if (episode + 1) % eval_every == 0:
            def dqn_policy(obs, info):
                return agent.select_action(
                    obs,
                    info.get("action_mask"),
                    training=False,
                )

            eval_result = evaluate_agent(
                env, dqn_policy,
                n_episodes=20, agent_name="dqn"
            )
            history["eval_rewards"].append(eval_result["mean_reward"])
            history["eval_findings"].append(eval_result["mean_findings"])

            # Save best model
            if eval_result["mean_reward"] > best_eval_reward:
                best_eval_reward = eval_result["mean_reward"]
                agent.save(save_path)
                if verbose:
                    print(f"  ✓ Best model saved (reward: {best_eval_reward:+.2f})")

    # Final evaluation
    if verbose:
        print(f"\n{'='*55}")
        print("  Final Evaluation vs Baselines")
        print(f"{'='*55}")

    def dqn_policy(obs, info):
        return agent.select_action(
            obs, info.get("action_mask"), training=False
        )

    dqn_eval    = evaluate_agent(env, dqn_policy,    50, "dqn")
    rand_result = train_random_baseline(env,  n_episodes=50)
    grdy_result = train_greedy_baseline(env,  n_episodes=50)

    if verbose:
        print(f"  Random:  reward={rand_result['mean_reward']:+.2f}  findings={rand_result['mean_findings']:.1f}")
        print(f"  Greedy:  reward={grdy_result['mean_reward']:+.2f}  findings={grdy_result['mean_findings']:.1f}")
        print(f"  DQN:     reward={dqn_eval['mean_reward']:+.2f}  findings={dqn_eval['mean_findings']:.1f}")

        improvement = (
            (dqn_eval["mean_reward"] - grdy_result["mean_reward"])
            / max(abs(grdy_result["mean_reward"]), 0.1) * 100
        )
        print(f"\n  DQN improvement over greedy: {improvement:+.1f}%")

    history["final_eval"] = {
        "dqn":    dqn_eval,
        "random": rand_result,
        "greedy": grdy_result,
    }

    # Save results
    save_results(history, f"dqn_training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    return history, agent


if __name__ == "__main__":
    history, agent = train_dqn(n_episodes=500, verbose=True)
    print("\nDQN training complete!")