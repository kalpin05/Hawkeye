import numpy as np
import sys
import os
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rl.state_encoder import (
    encode_state, get_action_mask,
    decode_action, STATE_DIM, ACTION_DIM,
)


# ─────────────────────────────────────────
# LOAD AGENT
# ─────────────────────────────────────────

def load_agent(mode: str = "ppo"):
    """Load trained RL agent by name."""
    models_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "models"
    )
    path = os.path.join(models_dir, f"{mode}_hawkeye.pth")

    if not os.path.exists(path):
        return None, f"Model not found: {path}. Train first with: python rl/train_{mode}.py"

    try:
        if mode == "ppo":
            from rl.agents.ppo_agent import PPOAgent
            agent = PPOAgent(STATE_DIM, ACTION_DIM)
            agent.load(path)
            return agent, None

        elif mode == "dqn":
            from rl.agents.dqn_agent import DQNAgent
            agent = DQNAgent(STATE_DIM, ACTION_DIM)
            agent.epsilon = 0.0  # No exploration during inference
            agent.load(path)
            return agent, None

        elif mode == "a2c":
            from rl.agents.a2c_agent import A2CAgent
            agent = A2CAgent(STATE_DIM, ACTION_DIM)
            agent.load(path)
            return agent, None

        else:
            return None, f"Unknown mode: {mode}. Use ppo, dqn, or a2c"

    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────
# GET NEXT ACTION
# ─────────────────────────────────────────

def get_next_action(
    agent,
    mode:         str,
    findings:     list,
    modules_run:  list,
    steps_taken:  int,
    max_steps:    int  = 10,
    target_features: dict = None,
) -> tuple:
    """
    Get next action from trained agent.
    Returns (action_idx, action_name, confidence)
    """
    state = encode_state(
        findings, modules_run,
        steps_taken, max_steps,
        target_features or {},
    )
    mask = get_action_mask(modules_run, steps_taken, max_steps)

    try:
        if mode == "ppo":
            action, log_prob, _ = agent.select_action(
                state, mask, training=False
            )
            confidence = float(np.exp(log_prob))

        elif mode == "dqn":
            import torch
            state_t = torch.FloatTensor(state).unsqueeze(0)
            import numpy as np2
            with torch.no_grad():
                q_vals = agent.online_net(state_t).squeeze(0)
                mask_t = torch.BoolTensor(mask)
                q_vals = q_vals.masked_fill(~mask_t, float("-inf"))
                action = int(q_vals.argmax().item())
                # Softmax for confidence
                valid_q   = q_vals[mask_t]
                conf_vals = torch.softmax(valid_q, dim=0)
                confidence = float(conf_vals.max().item())

        elif mode == "a2c":
            action, log_prob, _ = agent.select_action(
                state, mask, training=False
            )
            confidence = float(np.exp(log_prob))

        else:
            action     = 8  # stop
            confidence = 1.0

        action_name = decode_action(action)
        return action, action_name, confidence

    except Exception:
        return 8, "stop", 0.0


# ─────────────────────────────────────────
# RL-GUIDED SCAN
# ─────────────────────────────────────────

# Map action names to module functions
ACTION_TO_MODULE = {
    "run_headers":      "headers",
    "run_network_fast": "network_fast",
    "run_network_full": "network_full",
    "run_web":          "web",
    "run_api":          "api",
    "run_recon":        "recon",
    "run_subdomains":   "subdomains",
    "run_logic":        "logic",
    "stop":             None,
}


def run_module(action_name: str, target: str,
               proxy: str = "",
               stealth: bool = False,
               auth_session=None) -> list:
    """Run a HawkEye module by action name."""
    try:
        if action_name == "run_headers":
            from modules.header_checker import scan_headers
            return scan_headers(target)

        elif action_name in ("run_network_fast", "run_network_full"):
            from modules.network_scanner import scan_network
            fast = (action_name == "run_network_fast")
            return scan_network(target, fast=fast)

        elif action_name == "run_web":
            from modules.web_scanner import scan_web_smart
            return scan_web_smart(
                target, stealth=stealth,
                proxy=proxy, session=auth_session
            )

        elif action_name == "run_api":
            from modules.api_tester import scan_api
            return scan_api(target, fast=True)

        elif action_name == "run_recon":
            from modules.recon import scan_recon
            return scan_recon(target)

        elif action_name == "run_subdomains":
            from modules.subdomain_enum import discover_subdomains
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            result = discover_subdomains(domain, active=False)
            return [
                {"check": f"Subdomain: {s['subdomain']}",
                 "severity": "info", "module": "subdomains",
                 "detail": f"Live subdomain: {s['url']}"}
                for s in result.get("alive_subdomains", [])
            ]

        elif action_name == "run_logic":
            from modules.logic_scanner import scan_logic
            return scan_logic(target, session_a=auth_session)

    except Exception as e:
        return [{
            "check":    f"Module Error: {action_name}",
            "severity": "info",
            "detail":   str(e),
            "module":   "rl",
        }]
    return []


def rl_guided_scan(
    target:      str,
    mode:        str  = "ppo",
    max_steps:   int  = 10,
    proxy:       str  = "",
    stealth:     bool = False,
    auth_session=None,
    verbose:     bool = True,
) -> dict:
    """
    Full RL-guided scan.
    Agent decides which module to run next at each step.
    Returns findings + scan sequence used.
    """
    # Load agent
    agent, error = load_agent(mode)
    if error:
        return {
            "error":        error,
            "findings":     [],
            "scan_sequence":[],
            "mode":         mode,
        }

    all_findings  = []
    modules_run   = []
    scan_sequence = []
    steps_taken   = 0

    if verbose:
        print(f"\n  🤖 RL Mode: {mode.upper()} agent controlling scan")
        print(f"  Target: {target}")
        print(f"  Max steps: {max_steps}\n")

    while steps_taken < max_steps:
        # Get next action from agent
        action_idx, action_name, confidence = get_next_action(
            agent, mode,
            all_findings, modules_run,
            steps_taken, max_steps,
        )

        # Stop condition
        if action_name == "stop":
            if verbose:
                print(f"  Step {steps_taken+1}: Agent decided to STOP "
                      f"(confidence: {confidence:.0%})")
            break

        module_name = ACTION_TO_MODULE.get(action_name, "unknown")

        if verbose:
            print(f"  Step {steps_taken+1}: Agent chose "
                  f"[{action_name}] "
                  f"(confidence: {confidence:.0%})")

        # Run the chosen module
        new_findings = run_module(
            action_name, target, proxy, stealth, auth_session
        )

        # Filter info-only findings for reward calculation
        real_findings = [
            f for f in new_findings
            if f.get("severity") not in ("info",)
        ]

        all_findings.extend(new_findings)
        modules_run.append(module_name)
        scan_sequence.append({
            "step":         steps_taken + 1,
            "action":       action_name,
            "module":       module_name,
            "confidence":   confidence,
            "new_findings": len(new_findings),
            "new_vulns":    len(real_findings),
        })

        if verbose and new_findings:
            crits = sum(1 for f in new_findings
                        if f.get("severity") == "critical")
            highs = sum(1 for f in new_findings
                        if f.get("severity") == "high")
            print(f"         → {len(new_findings)} findings "
                  f"(critical:{crits} high:{highs})")

        steps_taken += 1

    # Summary
    counts = {"critical": 0, "high": 0, "medium": 0,
               "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    if verbose:
        print(f"\n  Scan complete — {steps_taken} steps, "
              f"{len(all_findings)} findings")
        print(f"  Modules used: {', '.join(modules_run)}")

    return {
        "target":        target,
        "mode":          mode,
        "findings":      all_findings,
        "scan_sequence": scan_sequence,
        "modules_run":   modules_run,
        "steps_taken":   steps_taken,
        "summary":       counts,
        "error":         None,
    }