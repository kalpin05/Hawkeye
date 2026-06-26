import { useState, useEffect } from "react";
import axios from "axios";

const API = "http://localhost:8000";

export default function StatsBar() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    axios.get(`${API}/stats`)
      .then(r => setStats(r.data))
      .catch(() => {});
  }, []);

  if (!stats) return null;

  const cards = [
    { label: "Total Scans",    value: stats.total_scans,    color: "#00FFFF" },
    { label: "Completed",      value: stats.completed,      color: "#00FF88" },
    { label: "Total Findings", value: stats.total_findings, color: "#FFCC00" },
    { label: "Critical",       value: stats.total_critical, color: "#FF4444" },
    { label: "High",           value: stats.total_high,     color: "#FF8800" },
  ];

  return (
    <div style={{ display: "flex", gap: "1rem", marginBottom: "2rem", flexWrap: "wrap" }}>
      {cards.map(c => (
        <div key={c.label} style={{
          background:   "#111",
          border:       `1px solid ${c.color}33`,
          borderTop:    `3px solid ${c.color}`,
          borderRadius: "8px",
          padding:      "1.2rem 1.5rem",
          flex:         "1",
          minWidth:     "140px",
          textAlign:    "center",
        }}>
          <div style={{ fontSize: "2rem", fontWeight: "bold", color: c.color }}>
            {c.value}
          </div>
          <div style={{ fontSize: "0.75rem", color: "#888",
            letterSpacing: "1px", marginTop: "4px" }}>
            {c.label.toUpperCase()}
          </div>
        </div>
      ))}
    </div>
  );
}