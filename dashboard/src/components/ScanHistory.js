import { useState, useEffect } from "react";
import axios from "axios";

const API = "http://localhost:8000";

const RISK_COLORS = {
  CRITICAL: "#FF4444", HIGH: "#FF8800",
  MEDIUM: "#FFCC00",   LOW: "#00CCFF",
  CLEAN: "#00FF88",    "": "#888",
};

const STATUS_COLORS = {
  completed: "#00FF88", running: "#00FFFF",
  pending: "#FFCC00",   failed: "#FF4444",
};

export default function ScanHistory({ onViewScan }) {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = () => {
    axios.get(`${API}/scans`)
      .then(r => { setScans(r.data); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchScans(); }, []);

  const deleteScan = async (id, e) => {
    e.stopPropagation();
    await axios.delete(`${API}/scan/${id}`);
    fetchScans();
  };

  if (loading) return (
    <div style={{ color: "#555", textAlign: "center", padding: "3rem" }}>
      Loading scans...
    </div>
  );

  if (!scans.length) return (
    <div style={{
      background: "#111", border: "1px dashed #333",
      borderRadius: "8px", padding: "3rem", textAlign: "center",
    }}>
      <div style={{ fontSize: "2rem", marginBottom: "8px" }}>🦅</div>
      <div style={{ color: "#555" }}>No scans yet. Start your first scan!</div>
    </div>
  );

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "center", marginBottom: "1rem" }}>
        <div style={{ color: "#888", fontSize: "0.8rem", letterSpacing: "2px" }}>
          {scans.length} SCAN{scans.length !== 1 ? "S" : ""}
        </div>
        <button onClick={fetchScans} style={{
          background: "transparent", border: "1px solid #333",
          color: "#888", padding: "4px 12px", borderRadius: "6px",
          cursor: "pointer", fontSize: "0.8rem",
        }}>↻ Refresh</button>
      </div>

      {scans.map(scan => (
        <div key={scan.id} onClick={() => onViewScan(scan)} style={{
          background:    "#111",
          border:        "1px solid #1E3A4A",
          borderLeft:    `4px solid ${RISK_COLORS[scan.risk_level] || "#333"}`,
          borderRadius:  "8px",
          padding:       "1rem 1.2rem",
          marginBottom:  "8px",
          cursor:        "pointer",
          display:       "flex",
          justifyContent:"space-between",
          alignItems:    "center",
        }}
          onMouseEnter={e => e.currentTarget.style.background = "#151515"}
          onMouseLeave={e => e.currentTarget.style.background = "#111"}
        >
          <div>
            <div style={{ fontWeight: "500", marginBottom: "4px" }}>
              {scan.target}
            </div>
            <div style={{ display: "flex", gap: "12px",
              fontSize: "0.8rem", color: "#666" }}>
              <span>Modules: {scan.modules.join(", ")}</span>
              <span>{new Date(scan.created_at).toLocaleString()}</span>
            </div>
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            {scan.risk_level && (
              <span style={{
                color:      RISK_COLORS[scan.risk_level],
                fontSize:   "0.8rem",
                fontWeight: "500",
              }}>
                {scan.risk_level}
              </span>
            )}
            <span style={{
              background:   `${STATUS_COLORS[scan.status]}22`,
              color:        STATUS_COLORS[scan.status],
              border:       `1px solid ${STATUS_COLORS[scan.status]}44`,
              fontSize:     "0.7rem",
              padding:      "2px 8px",
              borderRadius: "4px",
            }}>
              {scan.status}
            </span>
            {scan.total > 0 && (
              <span style={{ color: "#555", fontSize: "0.8rem" }}>
                {scan.total} findings
              </span>
            )}
            <button onClick={e => deleteScan(scan.id, e)} style={{
              background: "transparent", border: "none",
              color: "#333", cursor: "pointer", fontSize: "1rem",
              padding: "0 4px",
            }}
              onMouseEnter={e => e.currentTarget.style.color = "#FF4444"}
              onMouseLeave={e => e.currentTarget.style.color = "#333"}
            >
              ✕
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}