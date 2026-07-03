import { useState } from "react";
import axios from "axios";

const API = "http://localhost:8000";

export default function NewScan({ onScanStarted }) {
  const [target,  setTarget]  = useState("");
  const [modules, setModules] = useState({
    headers: true, network: false, web: false, api: false,
  });
  const [ai,      setAi]      = useState(false);
  const [fast,    setFast]    = useState(true);
  const [stealth, setStealth] = useState(false);
  const [proxy,   setProxy]   = useState("");
  const [showProxy, setShowProxy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");
  const [showAuth,     setShowAuth]     = useState(false);
  const [loginUrl,     setLoginUrl]     = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authToken,    setAuthToken]    = useState("");
  const toggle = key => setModules(m => ({ ...m, [key]: !m[key] }));

  const startScan = async () => {
    if (!target.trim()) { setError("Enter a target URL or IP"); return; }
    if (!Object.values(modules).some(Boolean)) {
      setError("Select at least one module"); return;
    }
    setError("");
    setLoading(true);
    try {
      const resp = await axios.post(`${API}/scan`, {
        target: target.trim(), ...modules, ai, fast, stealth, proxy,
      });
      onScanStarted(resp.data);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };
  const resp = await axios.post(`${API}/scan`, {
        target: target.trim(), ...modules, ai, fast, stealth, proxy,
        login_url:    loginUrl,
        username:     authUsername,
        password:     authPassword,
        token:        authToken,
        token_header: "Authorization",
      });
  const inputStyle = {
    width: "100%", padding: "12px 16px",
    background: "#111", border: "1px solid #1E3A4A",
    borderRadius: "8px", color: "#E0E0E0", fontSize: "1rem",
    outline: "none",
  };

  const moduleBtn = (key, label, color) => (
    <button key={key} onClick={() => toggle(key)} style={{
      padding:      "10px 20px",
      background:   modules[key] ? `${color}22` : "#111",
      border:       `1px solid ${modules[key] ? color : "#333"}`,
      borderRadius: "8px",
      color:        modules[key] ? color : "#666",
      cursor:       "pointer",
      fontSize:     "0.9rem",
      fontWeight:   modules[key] ? "500" : "normal",
    }}>
      {label}
    </button>
  );

  return (
    <div>
      <h2 style={{ color: "#00FFFF", fontSize: "0.85rem",
        letterSpacing: "3px", marginBottom: "1.5rem" }}>
        NEW SCAN
      </h2>

      <div style={{
        background: "#111", border: "1px solid #1E3A4A",
        borderRadius: "12px", padding: "2rem", maxWidth: "700px",
      }}>
        {/* Target */}
        <div style={{ marginBottom: "1.5rem" }}>
          <label style={{ display: "block", color: "#888",
            fontSize: "0.8rem", letterSpacing: "2px", marginBottom: "8px" }}>
            TARGET
          </label>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === "Enter" && startScan()}
            placeholder="https://example.com or 192.168.1.1"
            style={inputStyle}
          />
        </div>

        {/* Modules */}
        <div style={{ marginBottom: "1.5rem" }}>
          <label style={{ display: "block", color: "#888",
            fontSize: "0.8rem", letterSpacing: "2px", marginBottom: "8px" }}>
            MODULES
          </label>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {moduleBtn("headers", "🔒 Headers & SSL", "#00FFFF")}
            {moduleBtn("network", "🌐 Network",        "#00FF88")}
            {moduleBtn("web",     "🕷 Web Vulns",      "#FF8800")}
            {moduleBtn("api",     "⚡ API Security",   "#FF44FF")}
          </div>
        </div>

        {/* Options */}
        <div style={{ display: "flex", gap: "2rem", marginBottom: "1rem",
          flexWrap: "wrap" }}>
          {[
            { key: "ai",   label: "🤖 AI Triage", val: ai,   set: setAi   },
            { key: "fast", label: "⚡ Fast Mode",  val: fast, set: setFast },
          ].map(opt => (
            <label key={opt.key} style={{ display: "flex", alignItems: "center",
              gap: "8px", cursor: "pointer", color: "#CCC", fontSize: "0.9rem" }}>
              <input type="checkbox" checked={opt.val}
                onChange={() => opt.set(v => !v)}
                style={{ accentColor: "#00FFFF" }} />
              {opt.label}
            </label>
          ))}
        </div>
        {/* Authentication */}
        <div style={{
          background: "#0D1B2A", border: "1px solid #1E3A4A",
          borderRadius: "8px", padding: "1rem", marginBottom: "1rem",
        }}>
          <div style={{ color: "#00FF88", fontSize: "0.8rem",
            letterSpacing: "1px", marginBottom: "10px" }}>
            🔐 AUTHENTICATION (optional)
          </div>

          <label style={{ display: "flex", alignItems: "center",
            gap: "8px", cursor: "pointer", color: "#CCC",
            fontSize: "0.9rem", marginBottom: "10px" }}>
            <input type="checkbox"
              checked={showAuth}
              onChange={() => setShowAuth(v => !v)}
              style={{ accentColor: "#00FF88" }} />
            Login before scanning (finds vulnerabilities behind login)
          </label>

          {showAuth && (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <input
                value={loginUrl}
                onChange={e => setLoginUrl(e.target.value)}
                placeholder="Login URL (e.g. https://example.com/login)"
                style={{ ...inputStyle, fontSize: "0.85rem", padding: "10px 14px" }}
              />
              <div style={{ display: "flex", gap: "8px" }}>
                <input
                  value={authUsername}
                  onChange={e => setAuthUsername(e.target.value)}
                  placeholder="Username or email"
                  style={{ ...inputStyle, fontSize: "0.85rem",
                    padding: "10px 14px", flex: 1 }}
                />
                <input
                  type="password"
                  value={authPassword}
                  onChange={e => setAuthPassword(e.target.value)}
                  placeholder="Password"
                  style={{ ...inputStyle, fontSize: "0.85rem",
                    padding: "10px 14px", flex: 1 }}
                />
              </div>
              <div style={{ color: "#555", fontSize: "0.75rem" }}>
                OR use token auth:
              </div>
              <input
                value={authToken}
                onChange={e => setAuthToken(e.target.value)}
                placeholder="Bearer token / API key (optional)"
                style={{ ...inputStyle, fontSize: "0.85rem",
                  padding: "10px 14px",
                  fontFamily: "monospace" }}
              />
            </div>
          )}
        </div>

        {/* Evasion / WAF bypass section */}
        <div style={{
          background: "#0D1B2A", border: "1px solid #1E3A4A",
          borderRadius: "8px", padding: "1rem", marginBottom: "1.5rem",
        }}>
          <div style={{ color: "#FFAA00", fontSize: "0.8rem",
            letterSpacing: "1px", marginBottom: "10px",
            display: "flex", alignItems: "center", gap: "6px" }}>
            🛡️ WAF / FIREWALL EVASION
          </div>

          <label style={{ display: "flex", alignItems: "center",
            gap: "8px", cursor: "pointer", color: "#CCC",
            fontSize: "0.9rem", marginBottom: "10px" }}>
            <input type="checkbox" checked={stealth}
              onChange={() => setStealth(v => !v)}
              style={{ accentColor: "#FFAA00" }} />
            🥷 Stealth Mode — random delays + rotating user agents (slower but harder to block)
          </label>

          <label style={{ display: "flex", alignItems: "center",
            gap: "8px", cursor: "pointer", color: "#CCC",
            fontSize: "0.9rem", marginBottom: showProxy ? "10px" : "0" }}>
            <input type="checkbox" checked={showProxy}
              onChange={() => setShowProxy(v => !v)}
              style={{ accentColor: "#FFAA00" }} />
            🌐 Use Proxy (Tor / Burp Suite / Custom)
          </label>

          {showProxy && (
            <div>
              <input
                value={proxy}
                onChange={e => setProxy(e.target.value)}
                placeholder="http://127.0.0.1:9050 (Tor) or http://127.0.0.1:8080 (Burp)"
                style={{ ...inputStyle, fontSize: "0.85rem", padding: "10px 14px" }}
              />
              <div style={{ color: "#666", fontSize: "0.75rem", marginTop: "6px" }}>
                Tor default: <code style={{ color: "#FFAA00" }}>socks5h://127.0.0.1:9050</code>
                {" "}— requires Tor running locally. Burp Suite default:{" "}
                <code style={{ color: "#FFAA00" }}>http://127.0.0.1:8080</code>
              </div>
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div style={{ background: "#3D0000", border: "1px solid #FF4444",
            borderRadius: "6px", padding: "10px 14px",
            color: "#FF4444", fontSize: "0.9rem", marginBottom: "1rem" }}>
            {error}
          </div>
        )}

        {/* Disclaimer */}
        <div style={{ background: "#1A0D00", border: "1px solid #FF8800",
          borderRadius: "6px", padding: "10px 14px",
          color: "#FF8800", fontSize: "0.8rem", marginBottom: "1.5rem" }}>
          ⚠️ For authorized testing only. Only scan systems you own or have written permission to test.
        </div>

        {/* Submit */}
        <button onClick={startScan} disabled={loading} style={{
          width:        "100%",
          padding:      "14px",
          background:   loading ? "#1E3A4A" : "#00FFFF",
          border:       "none",
          borderRadius: "8px",
          color:        loading ? "#888" : "#000",
          fontSize:     "1rem",
          fontWeight:   "bold",
          cursor:       loading ? "not-allowed" : "pointer",
          letterSpacing: "1px",
        }}>
          {loading ? "Starting scan..." : "🦅 START SCAN"}
        </button>
      </div>
    </div>
  );
}