import gymnasium as gym
import numpy as np
import sys
import os
from typing import Optional, Dict, Any, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rl.state_encoder import (
    encode_state,
    get_action_mask,
    decode_action,
    STATE_DIM,
    ACTION_DIM,
    MODULES,
)


# ─────────────────────────────────────────
# REWARD CONSTANTS
# ─────────────────────────────────────────

REWARD_CRITICAL    = 10.0
REWARD_HIGH        = 5.0
REWARD_MEDIUM      = 2.0
REWARD_LOW         = 0.5
REWARD_INFO        = 0.0
REWARD_NO_FINDING  = -1.0
REWARD_REPEAT_MOD  = -2.0
REWARD_GOOD_STOP   = 3.0
REWARD_EARLY_STOP  = -5.0
REWARD_STEP_COST   = -0.1


class HawkEyeEnv(gym.Env):
    """
    Gymnasium environment wrapping HawkEye scanner.

    The RL agent learns to decide:
    - WHICH HawkEye module to run next
    - WHEN to stop scanning

    Goal: Maximize vulnerability findings with minimum wasted module runs.

    State:  40-dim float vector encoding scan progress and findings
    Action: Discrete(9) — which module to run or stop
    Reward: Based on new findings discovered per module run
    """

    metadata = {"render_modes": ["human", "ansi"]}

    def __init__(
        self,
        target:       str  = "http://testphp.vulnweb.com",
        max_steps:    int  = 10,
        use_real_scan:bool = False,
        render_mode:  Optional[str] = None,
    ):
        super().__init__()

        self.target        = target
        self.max_steps     = max_steps
        self.use_real_scan = use_real_scan
        self.render_mode   = render_mode

        # Gymnasium spaces
        self.observation_space = gym.spaces.Box(
            low=0.0, high=1.0,
            shape=(STATE_DIM,),
            dtype=np.float32,
        )
        self.action_space = gym.spaces.Discrete(ACTION_DIM)

        # Episode state
        self.findings        = []
        self.modules_run     = []
        self.steps_taken     = 0
        self.total_reward    = 0.0
        self.target_features = {}
        self.scan_history    = []

        # Simulated vulnerability profiles for training
        # (used when use_real_scan=False)
        self._sim_profiles = self._build_sim_profiles()

    # ─────────────────────────────────────────
    # SIMULATED SCAN PROFILES
    # ─────────────────────────────────────────

    def _build_sim_profiles(self) -> Dict:
        """
        Build simulated vulnerability profiles for training.
        Each profile represents a type of real-world target.
        Used for fast training without hitting real servers.
        """
        return {
            "wordpress_site": {
                "headers":    [
                    {"check": "Missing CSP",   "severity": "high",   "module": "headers"},
                    {"check": "Missing HSTS",  "severity": "high",   "module": "headers"},
                    {"check": "Exposed Server","severity": "medium", "module": "headers"},
                ],
                "web":        [
                    {"check": "XSS: Reflected","severity": "high",   "module": "web"},
                    {"check": "SQLi: MySQL",   "severity": "critical","module": "web"},
                ],
                "recon":      [
                    {"check": "Missing DMARC", "severity": "high",   "module": "recon"},
                    {"check": "Exposed .env",  "severity": "critical","module": "recon"},
                ],
                "network":    [
                    {"check": "Open Port: 22", "severity": "medium", "module": "network"},
                ],
                "api":        [],
                "subdomains": [
                    {"check": "Subdomain Takeover","severity": "critical","module": "recon"},
                ],
                "logic":      [],
                "js_heavy":   False,
            },
            "react_saas": {
                "headers":    [
                    {"check": "Missing CSP",   "severity": "high",   "module": "headers"},
                ],
                "web":        [],
                "recon":      [
                    {"check": "JS Secret: AWS Key","severity": "critical","module": "recon"},
                    {"check": "Missing DMARC",     "severity": "high",   "module": "recon"},
                ],
                "network":    [],
                "api":        [
                    {"check": "Broken Auth",       "severity": "critical","module": "api"},
                    {"check": "Missing Rate Limit","severity": "medium", "module": "api"},
                    {"check": "CORS Wildcard",     "severity": "medium", "module": "api"},
                ],
                "subdomains": [],
                "logic":      [
                    {"check": "IDOR: Horizontal",  "severity": "high",   "module": "logic"},
                ],
                "js_heavy":   True,
            },
            "ecommerce_php": {
                "headers":    [
                    {"check": "Missing HSTS",  "severity": "high",   "module": "headers"},
                    {"check": "Missing CSP",   "severity": "high",   "module": "headers"},
                    {"check": "Exposed Server","severity": "medium", "module": "headers"},
                ],
                "web":        [
                    {"check": "SQLi: MySQL",   "severity": "critical","module": "web"},
                    {"check": "XSS: Stored",   "severity": "high",   "module": "web"},
                    {"check": "IDOR: Order ID","severity": "high",   "module": "web"},
                ],
                "recon":      [
                    {"check": "Missing DMARC", "severity": "high",   "module": "recon"},
                    {"check": "Missing SPF",   "severity": "high",   "module": "recon"},
                ],
                "network":    [
                    {"check": "MySQL Exposed", "severity": "critical","module": "network"},
                    {"check": "FTP Open",      "severity": "high",   "module": "network"},
                ],
                "api":        [
                    {"check": "CORS Wildcard", "severity": "medium", "module": "api"},
                ],
                "subdomains": [
                    {"check": "Staging Exposed","severity": "high",  "module": "recon"},
                ],
                "logic":      [
                    {"check": "Price Manipulation","severity": "critical","module": "logic"},
                ],
                "js_heavy":   False,
            },
            "api_only": {
                "headers":    [],
                "web":        [],
                "recon":      [
                    {"check": "Missing DMARC","severity": "high",    "module": "recon"},
                ],
                "network":    [
                    {"check": "Redis Exposed","severity": "critical","module": "network"},
                ],
                "api":        [
                    {"check": "Broken Auth",  "severity": "critical","module": "api"},
                    {"check": "No Rate Limit","severity": "medium",  "module": "api"},
                    {"check": "BOLA/IDOR",    "severity": "high",   "module": "api"},
                    {"check": "JWT None Alg", "severity": "critical","module": "api"},
                ],
                "subdomains": [],
                "logic":      [],
                "js_heavy":   False,
            },
            "clean_site": {
                "headers":    [
                    {"check": "Missing Referrer-Policy","severity": "low","module": "headers"},
                ],
                "web":        [],
                "recon":      [],
                "network":    [],
                "api":        [],
                "subdomains": [],
                "logic":      [],
                "js_heavy":   False,
            },
        }

    def _get_random_profile(self):
        """Pick a random simulated target profile."""
        profiles = list(self._sim_profiles.keys())
        idx = self.np_random.integers(0, len(profiles))
        return self._sim_profiles[profiles[idx]]

    # ─────────────────────────────────────────
    # GYMNASIUM INTERFACE
    # ─────────────────────────────────────────

    def reset(
        self,
        seed:    Optional[int] = None,
        options: Optional[Dict] = None,
    ) -> Tuple[np.ndarray, Dict]:
        super().reset(seed=seed)

        self.findings     = []
        self.modules_run  = []
        self.steps_taken  = 0
        self.total_reward = 0.0
        self.scan_history = []

        # Pick simulated profile or prep for real scan
        if self.use_real_scan:
            self._current_profile   = None
            self.target_features    = {
                "js_heavy":       False,
                "has_login_form": False,
                "has_api":        False,
                "subdomain_count":0,
                "pages_found":    1,
            }
        else:
            self._current_profile = self._get_random_profile()
            self.target_features  = {
                "js_heavy":       self._current_profile.get("js_heavy", False),
                "has_login_form": True,
                "has_api":        len(self._current_profile.get("api", [])) > 0,
                "subdomain_count":len(self._current_profile.get("subdomains", [])),
                "pages_found":    5,
            }

        obs  = encode_state(
            self.findings, self.modules_run,
            self.steps_taken, self.max_steps,
            self.target_features,
        )
        info = {
            "action_mask":   get_action_mask(
                self.modules_run, self.steps_taken, self.max_steps
            ),
            "modules_run":   [],
            "findings_count": 0,
        }
        return obs, info

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        action_name = decode_action(action)
        reward      = REWARD_STEP_COST
        terminated  = False
        truncated   = False
        new_findings = []

        # ── Handle stop action ──
        if action_name == "stop" or action == 8:
            total_vuln = sum(
                1 for f in self.findings
                if f.get("severity") in ("critical", "high", "medium")
            )
            if total_vuln >= 3:
                reward += REWARD_GOOD_STOP
            elif self.steps_taken < 3:
                reward += REWARD_EARLY_STOP
            else:
                reward += 0.0
            terminated = True

        else:
            # Map action to module name
            action_module_map = {
                "run_headers":        "headers",
                "run_network_fast":   "network",
                "run_network_full":   "network",
                "run_web":            "web",
                "run_api":            "api",
                "run_recon":          "recon",
                "run_subdomains":     "subdomains",
                "run_logic":          "logic",
            }
            module = action_module_map.get(action_name, "")

            # ── Repeat module penalty ──
            if module in self.modules_run:
                reward += REWARD_REPEAT_MOD
            else:
                # ── Run module (real or simulated) ──
                if self.use_real_scan:
                    new_findings = self._run_real_module(module)
                else:
                    new_findings = self._run_simulated_module(module)

                self.modules_run.append(module)

                # ── Calculate reward ──
                if not new_findings:
                    reward += REWARD_NO_FINDING
                else:
                    for f in new_findings:
                        sev = f.get("severity", "info").lower()
                        if sev == "critical":
                            reward += REWARD_CRITICAL
                        elif sev == "high":
                            reward += REWARD_HIGH
                        elif sev == "medium":
                            reward += REWARD_MEDIUM
                        elif sev == "low":
                            reward += REWARD_LOW

                    self.findings.extend(new_findings)

        # ── Log step ──
        self.scan_history.append({
            "step":         self.steps_taken,
            "action":       action_name,
            "reward":       reward,
            "new_findings": len(new_findings),
        })

        self.steps_taken  += 1
        self.total_reward += reward

        # ── Truncate if max steps reached ──
        if self.steps_taken >= self.max_steps:
            truncated = True

        # ── Build next state ──
        obs = encode_state(
            self.findings, self.modules_run,
            self.steps_taken, self.max_steps,
            self.target_features,
        )

        info = {
            "action_mask":    get_action_mask(
                self.modules_run, self.steps_taken, self.max_steps
            ),
            "modules_run":    self.modules_run.copy(),
            "findings_count": len(self.findings),
            "new_findings":   new_findings,
            "scan_history":   self.scan_history,
        }

        if self.render_mode == "human":
            self.render()

        return obs, reward, terminated, truncated, info

    # ─────────────────────────────────────────
    # MODULE RUNNERS
    # ─────────────────────────────────────────

    def _run_simulated_module(self, module: str) -> list:
        """Run simulated module using profile data."""
        if not self._current_profile:
            return []
        findings = self._current_profile.get(module, [])
        # Add slight noise — sometimes miss 1 finding
        if findings and self.np_random.random() < 0.1:
            findings = findings[:-1]
        return findings.copy()

    def _run_real_module(self, module: str) -> list:
        """Run actual HawkEye module against real target."""
        try:
            if module == "headers":
                from modules.header_checker import scan_headers
                return scan_headers(self.target)
            elif module == "network":
                from modules.network_scanner import scan_network
                return scan_network(self.target, fast=True)
            elif module == "web":
                from modules.web_scanner import scan_web
                return scan_web(self.target)
            elif module == "api":
                from modules.api_tester import scan_api
                return scan_api(self.target, fast=True)
            elif module == "recon":
                from modules.recon import scan_recon
                return scan_recon(self.target)
            elif module == "subdomains":
                from modules.subdomain_enum import discover_subdomains
                result = discover_subdomains(self.target, active=False)
                return [
                    {"check": f"Subdomain: {s}", "severity": "info",
                     "module": "subdomains"}
                    for s in result.get("alive_subdomains", [])
                ]
            elif module == "logic":
                from modules.logic_scanner import scan_logic
                return scan_logic(self.target)
        except Exception:
            return []
        return []

    # ─────────────────────────────────────────
    # RENDER
    # ─────────────────────────────────────────

    def render(self):
        if self.render_mode == "ansi":
            return self._render_ansi()
        elif self.render_mode == "human":
            print(self._render_ansi())

    def _render_ansi(self) -> str:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1

        lines = [
            f"Step {self.steps_taken}/{self.max_steps}",
            f"Modules run: {', '.join(self.modules_run) or 'none'}",
            f"Findings: {len(self.findings)} "
            f"(C:{counts['critical']} H:{counts['high']} "
            f"M:{counts['medium']} L:{counts['low']})",
            f"Total reward: {self.total_reward:.2f}",
        ]
        return "\n".join(lines)

    def get_scan_summary(self) -> Dict:
        """Return summary of completed scan episode."""
        counts = {s: 0 for s in
                  ("critical", "high", "medium", "low", "info")}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1

        return {
            "target":        self.target,
            "modules_run":   self.modules_run,
            "total_findings":len(self.findings),
            "severity_counts": counts,
            "total_reward":  self.total_reward,
            "steps_taken":   self.steps_taken,
            "scan_history":  self.scan_history,
            "efficiency":    (
                len(self.findings) / max(len(self.modules_run), 1)
            ),
        }