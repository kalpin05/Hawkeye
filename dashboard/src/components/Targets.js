import { useState, useEffect } from "react";
import axios from "axios";
import {
  LineChart, Line, XAxis, YAxis,
  Tooltip, ResponsiveContainer,
} from "recharts";

const API = "http://localhost:8000";

const RISK_COLORS = {
  CRITICAL: "#FF4444", HIGH: "#FF8800",
  MEDIUM:   "#FFCC00", LOW:  "#00CCFF",
  CLEAN:    "#00FF88", "":   "#888",
};

const RISK_SCORES = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, CLEAN: 0,
};

export default function Targets({ onScanTarget }) {
  const [targets,     setTargets]     = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [showAdd,     setShowAdd]     = useState(false);
  const [domain,      setDomain]      = useState("");
  const [modules,     setModules]     = useState("headers,web");
  const [frequency,   setFrequency]   = useState("weekly");
  const [adding,      setAdding]      = useState(false);
  const [expandedId,  setExpandedId]  = useState(null);
  const [trendData,   setTrendData]   = useState({});
  const [diffData,    setDiffData]    = useState({});

  const fetchTargets = async () => {
    try {
      const r = await axios.get(`${API}/targets`);
      setTargets(r.data);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetchTargets(); }, []);

  const addTarget = async () => {
    if (!domain.trim()) return;
    setAdding(true);
    try {
      await axios.post(`${API}/targets`, {
        domain: domain.trim(), modules, frequency,
      });
      setDomain("");
      setShowAdd(false);
      fetchTargets();
    } catch (e) {
      alert(e.response?.data?.detail || "Failed to add target");
    }
    setAdding(false);
  };

  const deleteTarget = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm("Remove this target from monitoring?")) return;
    await axios.delete(`${API}/targets/${id}`);
    fetchTargets();
  };

  const triggerScan = async (id, domain, e) => {
    e.stopPropagation();
    try {
      await axios.post(`${API}/targets/${id}/scan`);
      alert(`Scan started for ${domain}`);
    } catch {}
  };

  const expandTarget = async (id) => {
    if (expandedId === id) { setExpandedId(null); return; }
    setExpandedId(id);

    // Fetch trend
    try {
      const r = await axios.get(`${API}/targets/${id}/trend`);
      setTrendData(prev => ({ ...prev, [id]: r.data }));
    } catch {}

    // Fetch latest diff
    try {
      const r = await axios.get(`${API}/targets/${id}/diff`);
      setDiffData(prev => ({ ...prev, [id]: r.data }));
    } catch {}
  };

  const inputStyle = {
    width: "100%", padding: "10px 14px",
    background: "#0D0D0D", border: "1px solid #1E3A4A",
    borderRadius: "8px", color: "#E0E0E0",
    fontSize: "0.9rem", outline: "none",
  };

  if (loading) return (
    <div style={{ color: "#555", textAlign: "center", padding: "3rem" }}>
      Loading monitored targets...
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: "1.5rem" }}>
        <h2 style={{ color: "#00FFFF", fontSize: "0.85rem",
          letterSpacing: "3px" }}>
          MONITORED TARGETS
        </h2>
        <button onClick={() => setShowAdd(v => !v)} style={{
          background: showAdd ? "#001D2D" : "#00FFFF",
          border:     "none", borderRadius: "6px",
          color:      showAdd ? "#00FFFF" : "#000",
          padding:    "8px 18px", cursor: "pointer",
          fontWeight: "bold", fontSize: "0.85rem",
        }}>
          {showAdd ? "Cancel" : "+ Add Target"}
        </button>
      </div>

      {/* Add target form */}
      {showAdd && (
        <div style={{
          background: "#111", border: "1px solid #1E3A4A",
          borderRadius: "12px", padding: "1.5rem",
          marginBottom: "1.5rem",
        }}>
          <div style={{ display: "flex", flexDirection: "column",
            gap: "10px" }}>
            <input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && addTarget()}
              placeholder="example.com (no http://)"
              style={inputStyle}
            />
            <div style={{ display: "flex", gap: "10px" }}>
              <select value={modules}
                onChange={e => setModules(e.target.value)}
                style={{ ...inputStyle, flex: 1 }}>
                <option value="headers">Headers only</option>
                <option value="headers,web">Headers + Web</option>
                <option value="headers,network">Headers + Network</option>
                <option value="headers,web,network,api">All modules</option>
              </select>
              <select value={frequency}
                onChange={e => setFrequency(e.target.value)}
                style={{ ...inputStyle, flex: 1 }}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="manual">Manual only</option>
              </select>
            </div>
            <button onClick={addTarget} disabled={adding} style={{
              background: adding ? "#333" : "#00FFFF",
              border: "none", borderRadius: "8px",
              color: adding ? "#888" : "#000",
              padding: "12px", cursor: adding ? "not-allowed" : "pointer",
              fontWeight: "bold",
            }}>
              {adding ? "Adding..." : "Add to Monitoring"}
            </button>
          </div>
        </div>
      )}

      {/* Target list */}
      {!targets.length ? (
        <div style={{
          background: "#111", border: "1px dashed #333",
          borderRadius: "8px", padding: "3rem", textAlign: "center",
        }}>
          <div style={{ fontSize: "2rem", marginBottom: "8px" }}>🎯</div>
          <div style={{ color: "#555" }}>
            No targets monitored yet. Add a domain to track its security over time.
          </div>
        </div>
      ) : (
        targets.map(target => {
          const trend  = trendData[target.id];
          const diff   = diffData[target.id];
          const isOpen = expandedId === target.id;

          const chartPoints = trend?.scans?.map(s => ({
            date:  s.created_at?.split("T")[0] || "",
            score: RISK_SCORES[s.risk_level] || 0,
            risk:  s.risk_level || "CLEAN",
          })) || [];

          return (
            <div key={target.id} style={{
              background:   "#111",
              border:       "1px solid #1E3A4A",
              borderRadius: "12px",
              marginBottom: "10px",
              overflow:     "hidden",
            }}>
              {/* Target row */}
              <div
                onClick={() => expandTarget(target.id)}
                style={{
                  padding:        "1rem 1.2rem",
                  display:        "flex",
                  justifyContent: "space-between",
                  alignItems:     "center",
                  cursor:         "pointer",
                }}
                onMouseEnter={e => e.currentTarget.style.background = "#151515"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div>
                  <div style={{ fontWeight: "500", marginBottom: "4px" }}>
                    {target.domain}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "#666" }}>
                    Modules: {target.modules} ·
                    Frequency: {target.frequency}
                  </div>
                </div>

                <div style={{ display: "flex", gap: "8px",
                  alignItems: "center" }}>
                  {/* Trend indicator */}
                  {trend && (
                    <span style={{
                      fontSize: "0.75rem",
                      color: trend.trend === "improving" ? "#00FF88" :
                             trend.trend === "worsening" ? "#FF4444" :
                             "#888",
                    }}>
                      {trend.trend === "improving" ? "↓ Improving" :
                       trend.trend === "worsening" ? "↑ Worsening" :
                       "→ Stable"}
                    </span>
                  )}

                  <button
                    onClick={e => triggerScan(target.id, target.domain, e)}
                    style={{
                      background: "transparent",
                      border:     "1px solid #00FFFF",
                      color:      "#00FFFF",
                      padding:    "4px 12px",
                      borderRadius:"6px",
                      cursor:     "pointer",
                      fontSize:   "0.8rem",
                    }}
                  >
                    Scan Now
                  </button>

                  <button
                    onClick={e => deleteTarget(target.id, e)}
                    style={{
                      background: "transparent", border: "none",
                      color: "#333", cursor: "pointer", fontSize: "1rem",
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = "#FF4444"}
                    onMouseLeave={e => e.currentTarget.style.color = "#333"}
                  >
                    ✕
                  </button>

                  <span style={{ color: "#555" }}>
                    {isOpen ? "▲" : "▼"}
                  </span>
                </div>
              </div>

              {/* Expanded view */}
              {isOpen && (
                <div style={{
                  borderTop: "1px solid #1E3A4A",
                  padding:   "1.2rem",
                }}>
                  {/* Trend chart */}
                  {chartPoints.length > 1 && (
                    <div style={{ marginBottom: "1.5rem" }}>
                      <div style={{ color: "#888", fontSize: "0.75rem",
                        letterSpacing: "2px", marginBottom: "8px" }}>
                        RISK TREND
                      </div>
                      <ResponsiveContainer width="100%" height={150}>
                        <LineChart data={chartPoints}>
                          <XAxis dataKey="date" stroke="#555"
                            tick={{ fontSize: 11 }} />
                          <YAxis stroke="#555" domain={[0, 5]}
                            tick={{ fontSize: 11 }}
                            tickFormatter={v => (
                              ["", "LOW", "MED", "HIGH", "HIGH+", "CRIT"][v] || v
                            )} />
                          <Tooltip
                            contentStyle={{
                              background: "#111",
                              border: "1px solid #333",
                            }}
                            formatter={(v, n, p) => [
                              p.payload.risk, "Risk"
                            ]}
                          />
                          <Line
                            type="monotone" dataKey="score"
                            stroke="#00FFFF" strokeWidth={2}
                            dot={{ fill: "#00FFFF", r: 4 }}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  {chartPoints.length === 1 && (
                    <div style={{ color: "#555", fontSize: "0.85rem",
                      marginBottom: "1rem" }}>
                      Run at least 2 scans to see trend chart.
                    </div>
                  )}

                  {chartPoints.length === 0 && (
                    <div style={{ color: "#555", fontSize: "0.85rem",
                      marginBottom: "1rem" }}>
                      No completed scans yet — click "Scan Now" to start.
                    </div>
                  )}

                  {/* Diff report */}
                  {diff && !diff.message && (
                    <div>
                      <div style={{ color: "#888", fontSize: "0.75rem",
                        letterSpacing: "2px", marginBottom: "10px" }}>
                        LATEST DIFF REPORT
                      </div>
                      <div style={{ display: "flex", gap: "10px",
                        flexWrap: "wrap", marginBottom: "1rem" }}>
                        {[
                          { label: "New",      val: diff.new_count,
                            color: "#FF4444" },
                          { label: "Fixed",    val: diff.fixed_count,
                            color: "#00FF88" },
                          { label: "Worsened", val: diff.worsened_count,
                            color: "#FF8800" },
                        ].map(item => (
                          <div key={item.label} style={{
                            background:   "#0D0D0D",
                            border:       `1px solid ${item.color}44`,
                            borderTop:    `3px solid ${item.color}`,
                            borderRadius: "8px",
                            padding:      "10px 20px",
                            textAlign:    "center",
                            flex:         1,
                          }}>
                            <div style={{ fontSize: "1.8rem",
                              fontWeight: "bold", color: item.color }}>
                              {item.val}
                            </div>
                            <div style={{ fontSize: "0.75rem",
                              color: "#888" }}>
                              {item.label.toUpperCase()}
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* New findings */}
                      {diff.diff?.diff?.new?.length > 0 && (
                        <div>
                          <div style={{ color: "#FF4444",
                            fontSize: "0.8rem", marginBottom: "6px" }}>
                            🔴 NEW FINDINGS
                          </div>
                          {diff.diff.diff.new.map((f, i) => (
                            <div key={i} style={{
                              background: "#1A0000",
                              borderLeft: "3px solid #FF4444",
                              borderRadius: "4px",
                              padding: "8px 12px",
                              marginBottom: "4px",
                              fontSize: "0.85rem",
                            }}>
                              <span style={{ color: "#FF4444",
                                marginRight: "8px" }}>
                                {f.severity?.toUpperCase()}
                              </span>
                              {f.check}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Fixed findings */}
                      {diff.diff?.diff?.fixed?.length > 0 && (
                        <div style={{ marginTop: "10px" }}>
                          <div style={{ color: "#00FF88",
                            fontSize: "0.8rem", marginBottom: "6px" }}>
                            ✅ FIXED SINCE LAST SCAN
                          </div>
                          {diff.diff.diff.fixed.map((f, i) => (
                            <div key={i} style={{
                              background: "#001A00",
                              borderLeft: "3px solid #00FF88",
                              borderRadius: "4px",
                              padding: "8px 12px",
                              marginBottom: "4px",
                              fontSize: "0.85rem",
                            }}>
                              <span style={{ color: "#00FF88",
                                marginRight: "8px" }}>
                                {f.severity?.toUpperCase()}
                              </span>
                              {f.check}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {diff?.message && (
                    <div style={{ color: "#555", fontSize: "0.85rem" }}>
                      {diff.message}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}