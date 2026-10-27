import numpy as np
from typing import List, Dict

# ─────────────────────────────────────────
# STATE SPACE DEFINITION
# ─────────────────────────────────────────

# State vector size = 40 features
STATE_DIM = 40

# Module indices
MODULES = [
    "headers",   # 0
    "network",   # 1
    "web",       # 2
    "api",       # 3
    "recon",     # 4
    "subdomains",# 5
    "logic",     # 6
]

# Action space
ACTIONS = {
    0: "run_headers",
    1: "run_network_fast",
    2: "run_network_full",
    3: "run_web",
    4: "run_api",
    5: "run_recon",
    6: "run_subdomains",
    7: "run_logic",
    8: "stop",
}
ACTION_DIM = len(ACTIONS)

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high":     0.7,
    "medium":   0.4,
    "low":      0.2,
    "info":     0.0,
}


def encode_state(
    findings:        List[Dict],
    modules_run:     List[str],
    steps_taken:     int,
    max_steps:       int,
    target_features: Dict = None,
) -> np.ndarray:
    """
    Convert HawkEye scan state to a fixed-size numeric vector.

    State vector (40 features):
    [0-4]   Severity counts (critical, high, medium, low, info)
    [5-9]   Normalized severity counts
    [10]    Total findings
    [11]    Unique modules in findings
    [12-18] Modules run flags (one per module)
    [19]    Steps taken (normalized)
    [20]    Remaining steps (normalized)
    [21]    Has critical findings
    [22]    Has high findings
    [23]    Has web findings
    [24]    Has network findings
    [25]    Has header findings
    [26]    Has API findings
    [27]    Has recon findings
    [28]    Has logic findings
    [29]    JS heavy site indicator
    [30]    Has login form
    [31]    Has API endpoints
    [32]    Subdomain count (normalized)
    [33]    Pages discovered (normalized)
    [34]    Finding density (findings per module run)
    [35]    Critical finding rate
    [36]    High finding rate
    [37]    Wasted module rate
    [38]    Scan progress (normalized)
    [39]    Exploration bonus
    """
    state = np.zeros(STATE_DIM, dtype=np.float32)

    # Count severities
    counts = {s: 0 for s in SEVERITY_WEIGHTS}
    module_findings = {m: 0 for m in MODULES}

    for f in findings:
        sev = f.get("severity", "info").lower()
        mod = f.get("module", "").lower()
        if sev in counts:
            counts[sev] += 1
        for m in MODULES:
            if m in mod:
                module_findings[m] += 1

    total = len(findings)

    # [0-4] Raw severity counts (capped at 20)
    state[0] = min(counts["critical"], 20) / 20.0
    state[1] = min(counts["high"],     20) / 20.0
    state[2] = min(counts["medium"],   20) / 20.0
    state[3] = min(counts["low"],      20) / 20.0
    state[4] = min(counts["info"],     20) / 20.0

    # [5-9] Normalized severity rates
    if total > 0:
        state[5] = counts["critical"] / total
        state[6] = counts["high"]     / total
        state[7] = counts["medium"]   / total
        state[8] = counts["low"]      / total
        state[9] = counts["info"]     / total

    # [10] Total findings normalized
    state[10] = min(total, 50) / 50.0

    # [11] Unique modules in findings
    unique_mods = len(set(
        f.get("module", "") for f in findings
        if f.get("module")
    ))
    state[11] = unique_mods / len(MODULES)

    # [12-18] Modules run flags
    for i, mod in enumerate(MODULES):
        state[12 + i] = 1.0 if mod in modules_run else 0.0

    # [19-20] Step progress
    state[19] = steps_taken / max(max_steps, 1)
    state[20] = (max_steps - steps_taken) / max(max_steps, 1)

    # [21-22] Has critical/high
    state[21] = 1.0 if counts["critical"] > 0 else 0.0
    state[22] = 1.0 if counts["high"]     > 0 else 0.0

    # [23-28] Per-module finding flags
    state[23] = 1.0 if module_findings.get("web",       0) > 0 else 0.0
    state[24] = 1.0 if module_findings.get("network",   0) > 0 else 0.0
    state[25] = 1.0 if module_findings.get("headers",   0) > 0 else 0.0
    state[26] = 1.0 if module_findings.get("api",       0) > 0 else 0.0
    state[27] = 1.0 if module_findings.get("recon",     0) > 0 else 0.0
    state[28] = 1.0 if module_findings.get("logic",     0) > 0 else 0.0

    # [29-31] Target features
    if target_features:
        state[29] = 1.0 if target_features.get("js_heavy")       else 0.0
        state[30] = 1.0 if target_features.get("has_login_form")  else 0.0
        state[31] = 1.0 if target_features.get("has_api")         else 0.0
        state[32] = min(target_features.get("subdomain_count", 0), 20) / 20.0
        state[33] = min(target_features.get("pages_found", 0),    50) / 50.0

    # [34-37] Efficiency metrics
    modules_run_count = max(len(modules_run), 1)
    state[34] = min(total, 50) / (50.0 * modules_run_count)  # Finding density
    state[35] = counts["critical"] / (modules_run_count * 5)  # Critical rate
    state[36] = counts["high"]     / (modules_run_count * 5)  # High rate
    wasted    = sum(
        1 for m in modules_run
        if module_findings.get(m, 0) == 0
    )
    state[37] = wasted / modules_run_count  # Wasted module rate

    # [38] Scan progress
    state[38] = steps_taken / max(max_steps, 1)

    # [39] Exploration bonus (reward unexplored modules)
    unexplored = len([m for m in MODULES if m not in modules_run])
    state[39]  = unexplored / len(MODULES)

    return state


def decode_action(action: int) -> str:
    """Convert action index to action name."""
    return ACTIONS.get(action, "stop")


def get_action_mask(modules_run: List[str],
                    steps_taken: int,
                    max_steps: int) -> np.ndarray:
    """
    Return boolean mask of valid actions.
    Prevents re-running completed modules.
    """
    mask = np.ones(ACTION_DIM, dtype=bool)

    # Map actions to modules
    action_module_map = {
        0: "headers",
        1: "network",
        2: "network",
        3: "web",
        4: "api",
        5: "recon",
        6: "subdomains",
        7: "logic",
        8: None,  # stop is always valid
    }

    for action_idx, module in action_module_map.items():
        if module and module in modules_run:
            mask[action_idx] = False

    # If max steps reached — only allow stop
    if steps_taken >= max_steps - 1:
        mask[:] = False
        mask[8] = True

    # Always allow stop
    mask[8] = True

    return mask