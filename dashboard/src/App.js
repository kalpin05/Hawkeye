import { useState } from "react";
import NewScan from "./components/NewScan";
import ScanHistory from "./components/ScanHistory";
import ScanResults from "./components/ScanResults";
import StatsBar from "./components/StatsBar";

export default function App() {
  const [page, setPage]         = useState("dashboard");
  const [activeScan, setActiveScan] = useState(null);

  return (
    <div style={{
      minHeight:  "100vh",
      background: "#0D0D0D",
      color:      "#E0E0E0",
      fontFamily: "'Segoe UI', Arial, sans-serif",
    }}>
      {/* NAV */}
      <nav style={{
        background:   "#0D1B2A",
        borderBottom: "2px solid #00FFFF",
        padding:      "0 2rem",
        display:      "flex",
        alignItems:   "center",
        gap:          "2rem",
        height:       "56px",
      }}>
        <div style={{
          color:         "#00FFFF",
          fontWeight:    "bold",
          fontSize:      "1.2rem",
          letterSpacing: "3px",
          marginRight:   "2rem",
        }}>
          🦅 HAWKEYE
        </div>
        {[
          { id: "dashboard", label: "Dashboard" },
          { id: "newscan",   label: "New Scan"  },
          { id: "history",   label: "History"   },
        ].map(item => (
          <button key={item.id} onClick={() => setPage(item.id)} style={{
            background:   page === item.id ? "#00FFFF22" : "transparent",
            border:       page === item.id ? "1px solid #00FFFF" : "1px solid transparent",
            color:        page === item.id ? "#00FFFF" : "#888",
            padding:      "6px 16px",
            borderRadius: "6px",
            cursor:       "pointer",
            fontSize:     "0.9rem",
          }}>
            {item.label}
          </button>
        ))}
      </nav>

      {/* CONTENT */}
      <div style={{ padding: "2rem", maxWidth: "1200px", margin: "0 auto" }}>
        {page === "dashboard" && (
          <>
            <StatsBar />
            <h2 style={{ color: "#00FFFF", marginBottom: "1rem",
              fontSize: "0.85rem", letterSpacing: "3px" }}>
              RECENT SCANS
            </h2>
            <ScanHistory onViewScan={(scan) => {
              setActiveScan(scan);
              setPage("results");
            }} />
          </>
        )}
        {page === "newscan" && (
          <NewScan onScanStarted={(scan) => {
            setActiveScan(scan);
            setPage("results");
          }} />
        )}
        {page === "history" && (
          <ScanHistory onViewScan={(scan) => {
            setActiveScan(scan);
            setPage("results");
          }} />
        )}
        {page === "results" && activeScan && (
          <ScanResults
            scan={activeScan}
            onBack={() => setPage("history")}
          />
        )}
      </div>
    </div>
  );
}