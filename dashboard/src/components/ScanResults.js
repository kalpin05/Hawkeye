import { useState, useEffect } from "react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, Cell,
} from "recharts";

const API = "http://localhost:8000";

const SEV_COLORS = {
  critical: "#FF4444",
  high:     "#FF8800",
  medium:   "#FFCC00",
  low:      "#00CCFF",
  info:     "#555555",
};

const RISK_COLORS = {
  CRITICAL: "#FF4444",
  HIGH:     "#FF8800",
  MEDIUM:   "#FFCC00",
  LOW:      "#00CCFF",
  CLEAN:    "#00FF88",
};

export default function ScanResults({ scan, onBack }) {
  const [data,     setData]     = useState(scan);
  const [loading,  setLoading]  = useState(true);
  const [expanded, setExpanded] = useState({});

  // Poll until completed
  useEffect(() => {
    if (data.status === "completed" || data.status === "failed") {
      setLoading(false);
      return;
    }
    const interval = setInterval(async () => {
      try {
        const resp = await axios.get(`${API}/scan/${scan.scan_id || scan.id}`);
        setData(resp.data);
        if (resp.data.status === "completed" || resp.data.status === "failed") {
          setLoading(false);
          clearInterval(interval);
        }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [scan]);

  const toggleExpand = idx =>
    setExpanded(e => ({ ...e, [idx]: !e[idx] }));

  const scanId   = data.scan_id || data.id;
  const summary  = data.summary || {};
  const findings = data.findings || [];
  const riskColor = RISK_COLORS[data.risk_level] || "#888";

  const chartData = [
    { name: "Critical", value: summary.critical || 0, color: "#FF4444" },
    { name: "High",     value: summary.high     || 0, color: "#FF8800" },
    { name: "Medium",   value: summary.medium   || 0, color: "#FFCC00" },
    { name: "Low",      value: summary.low      || 0, color: "#00CCFF" },
    { name: "Info",     value: summary.info     || 0, color: "#555555" },
  ];

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center",
        gap: "1rem", marginBottom: "1.5rem" }}>
        <button onClick={onBack} style={{
          background: "transparent", border: "1px solid #333",
          color: "#888", padding: "6px 14px", borderRadius: "6px",
          cursor: "pointer",
        }}>← Back</button>
        <h2 style={{ color: "#00FFFF", fontSize: "0.85rem",
          letterSpacing: "3px" }}>SCAN RESULTS</h2>
      </div>

      {/* Status */}
      {(data.status === "pending" || data.status === "running") && (
        <div style={{
          background: "#001D2D", border: "1px solid #00FFFF",
          borderRadius: "8px", padding: "1.5rem", textAlign: "center",
          marginBottom: "1.5rem",
        }}>
          <div style={{ fontSize: "1.5rem", marginBottom: "8px" }}>🔍</div>
          <div style={{ color: "#00FFFF", fontWeight: "500" }}>
            Scanning {data.target}...
          </div>
          <div style={{ color: "#888", fontSize: "0.85rem", marginTop: "4px" }}>
            Status: {data.status} — refreshing every 2 seconds
          </div>
        </div>
      )}

      {data.status === "failed" && (
        <div style={{
          background: "#3D0000", border: "1px solid #FF4444",
          borderRadius: "8px", padding: "1.5rem", marginBottom: "1.5rem",
        }}>
          <div style={{ color: "#FF4444" }}>❌ Scan failed. Check target and try again.</div>
        </div>
      )}

      {data.status === "completed" && (
        <>
          {/* Summary cards */}
          <div style={{ display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
            gap: "1rem", marginBottom: "1.5rem" }}>
            <div style={{
              background: "#111", borderRadius: "8px",
              borderTop: `3px solid ${riskColor}`,
              padding: "1rem", textAlign: "center",
            }}>
              <div style={{ fontSize: "1.8rem", fontWeight: "bold", color: riskColor }}>
                {data.risk_level}
              </div>
              <div style={{ color: "#888", fontSize: "0.75rem",
                letterSpacing: "1px" }}>RISK LEVEL</div>
            </div>
            {["total", "critical", "high", "medium", "low"].map(k => (
              <div key={k} style={{
                background: "#111", borderRadius: "8px",
                borderTop: `3px solid ${SEV_COLORS[k] || "#00FFFF"}`,
                padding: "1rem", textAlign: "center",
              }}>
                <div style={{ fontSize: "1.8rem", fontWeight: "bold",
                  color: SEV_COLORS[k] || "#00FFFF" }}>
                  {summary[k] || 0}
                </div>
                <div style={{ color: "#888", fontSize: "0.75rem",
                  letterSpacing: "1px" }}>{k.toUpperCase()}</div>
              </div>
            ))}
          </div>

          {/* Chart */}
          {findings.length > 0 && (
            <div style={{
              background: "#111", border: "1px solid #1E3A4A",
              borderRadius: "8px", padding: "1.5rem", marginBottom: "1.5rem",
            }}>
              <div style={{ color: "#888", fontSize: "0.8rem",
                letterSpacing: "2px", marginBottom: "1rem" }}>
                FINDINGS BY SEVERITY
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={chartData}>
                  <XAxis dataKey="name" stroke="#555" />
                  <YAxis stroke="#555" allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: "#111", border: "1px solid #333" }}
                    labelStyle={{ color: "#CCC" }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Download buttons */}
          <div style={{ display: "flex", gap: "10px", marginBottom: "1.5rem" }}>
            <a href={`${API}/report/${scanId}/json`} download style={{
              padding: "8px 18px", background: "#1E3A4A",
              color: "#00FFFF", borderRadius: "6px",
              textDecoration: "none", fontSize: "0.85rem",
            }}>
              ⬇ JSON Report
            </a>
            <a href={`${API}/report/${scanId}/html`} download style={{
              padding: "8px 18px", background: "#1E3A4A",
              color: "#00FF88", borderRadius: "6px",
              textDecoration: "none", fontSize: "0.85rem",
            }}>
              ⬇ HTML Report
            </a>
          </div>

          {/* Findings list */}
          <div style={{ color: "#888", fontSize: "0.8rem",
            letterSpacing: "2px", marginBottom: "1rem" }}>
            FINDINGS ({findings.length})
          </div>
          {findings.map((f, i) => {
            const sev   = f.severity?.toLowerCase() || "info";
            const color = SEV_COLORS[sev] || "#888";
            const t     = f.ai_triage || {};
            return (
              <div key={i} onClick={() => toggleExpand(i)} style={{
                background:   "#111",
                borderLeft:   `4px solid ${color}`,
                borderRadius: "8px",
                padding:      "1rem 1.2rem",
                marginBottom: "8px",
                cursor:       "pointer",
              }}>
                <div style={{ display: "flex",
                  justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                    <span style={{
                      background: color, color: "#000",
                      fontSize: "0.7rem", fontWeight: "bold",
                      padding: "2px 8px", borderRadius: "4px",
                    }}>
                      {sev.toUpperCase()}
                    </span>
                    <span style={{ fontSize: "0.9rem" }}>{f.check}</span>
                  </div>
                  <span style={{ color: "#555", fontSize: "0.8rem" }}>
                    {expanded[i] ? "▲" : "▼"}
                  </span>
                </div>

                {expanded[i] && (
                  <div style={{ marginTop: "10px", paddingTop: "10px",
                    borderTop: "1px solid #222" }}>
                    <p style={{ color: "#AAA", fontSize: "0.85rem",
                      marginBottom: "8px" }}>{f.detail}</p>
                    {f.url && (
                      <p style={{ color: "#555", fontSize: "0.8rem",
                        marginBottom: "8px" }}>URL: {f.url}</p>
                    )}
                    {t.explanation && (
                      <div style={{
                        background: "#0D1B2A", borderRadius: "6px",
                        padding: "10px 12px", marginTop: "8px",
                      }}>
                        <div style={{ color: "#00FFFF", fontSize: "0.75rem",
                          letterSpacing: "1px", marginBottom: "6px" }}>
                          🤖 AI TRIAGE — Risk: {t.risk_score}/10
                        </div>
                        <p style={{ color: "#CCC", fontSize: "0.85rem",
                          marginBottom: "6px" }}>{t.explanation}</p>
                        <p style={{ color: "#AAA", fontSize: "0.85rem",
                          marginBottom: "6px" }}>
                          <strong>Impact:</strong> {t.impact}
                        </p>
                        <div style={{
                          background: "#0D1B0D", border: "1px solid #1A3A1A",
                          borderRadius: "4px", padding: "8px 10px",
                          color: "#90EE90", fontSize: "0.8rem",
                        }}>
                          <strong>Fix:</strong> {t.fix}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}