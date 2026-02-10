import { useEffect, useState } from "react";
import { fetchAlerts, fetchMlStatus } from "../services/api";

function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [severity, setSeverity] = useState("");
  const [mlStatus, setMlStatus] = useState(null);

  async function loadMlStatus() {
  try {
    const data = await fetchMlStatus();
    setMlStatus(data);
  } catch (err) {
    setMlStatus(null);
  }
}

  async function loadAlerts() {
    const data = await fetchAlerts(
      severity ? { severity } : {}
    );
    setAlerts(data);
  }

  useEffect(() => {
    loadAlerts();
    loadMlStatus();
    const interval = setInterval(loadAlerts, 5000);
    const mlInterval = setInterval(loadMlStatus, 30000);
    return () => {
      clearInterval(interval);
      clearInterval(mlInterval);
    };
  }, [severity]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/alerts");

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "new_alert") {
        setAlerts((prev) => [msg.data, ...prev]);
      }
    };

    return () => ws.close();
  }, []);

  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const getTime = (alert) => {
    const value = alert.timestamp || alert.ingested_at || alert.event_time;
    if (!value) return "-";
    return new Date(value).toLocaleString("en-US", {
      timeZone,
      hour12: true
      
    });
  };

  const nowLocal = new Date().toLocaleString("en-US", { timeZone, hour12: true });
  const nowUtc = new Date().toISOString().replace("T", " ").replace("Z", " UTC");

  const severityColor = (sev) => {
    if (sev === "high") return "#ef4444";
    if (sev === "medium") return "#f59e0b";
    if (sev === "low") return "#22c55e";
    return "#94a3b8";
  };

  const badgeStyle = (kind) => ({
    display: "inline-block",
    padding: "2px 8px",
    borderRadius: "999px",
    fontSize: "11px",
    textTransform: "uppercase",
    letterSpacing: "0.4px",
    background:
      kind === "ueba_rare_entity"
        ? "rgba(14, 165, 233, 0.15)"
        : kind === "ueba_incident"
        ? "rgba(239, 68, 68, 0.15)"
        : "rgba(148, 163, 184, 0.15)",
    color:
      kind === "ueba_rare_entity"
        ? "#0ea5e9"
        : kind === "ueba_incident"
        ? "#ef4444"
        : "#94a3b8",
    border:
      kind === "ueba_rare_entity"
        ? "1px solid rgba(14, 165, 233, 0.35)"
        : kind === "ueba_incident"
        ? "1px solid rgba(239, 68, 68, 0.35)"
        : "1px solid rgba(148, 163, 184, 0.35)"
  });

  const getType = (alert) => alert.alert_type || alert.incident || "alert";
  const getDescription = (alert) => alert.description || alert.incident || "-";
  const getAnomalyScore = (alert) => {
    const value = alert.anomaly_score;
    if (value === null || value === undefined) return "-";
    if (Number.isNaN(Number(value))) return String(value);
    return Number(value).toFixed(3);
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1 style={{ fontSize: "26px", marginBottom: "10px" }}>
        SentinelAI - SOC Dashboard
      </h1>

      <div style={{ marginBottom: "10px", fontSize: "12px", color: "#94a3b8" }}>
        Browser TZ: {timeZone} | Local now: {nowLocal} | UTC now: {nowUtc}
        {mlStatus && (
          <>
            {" "}| ML: {mlStatus.trained ? "trained" : "untrained"} | Version: {mlStatus.model_version || "-"} | Samples: {mlStatus.last_train_samples ?? "-"}
          </>
        )}
      </div>

      <div style={{ marginBottom: "15px" }}>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          style={{ padding: "6px" }}
        >
          <option value="">All Severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#1e293b" }}>
            <th style={th}>Time</th>
            <th style={th}>Type</th>
            <th style={th}>IP</th>
            <th style={th}>Severity</th>
            <th style={th}>Incident</th>
            <th style={th}>Confidence</th>
            <th style={th}>Risk</th>
            <th style={th}>Kill Chain</th>
            <th style={th}>Anomaly Score</th>
            <th style={th}>Description</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a._id} style={{ borderBottom: "1px solid #334155" }}>
              <td style={td}>{getTime(a)}</td>
              <td style={td}>
                <span style={badgeStyle(a.alert_type)}>{getType(a)}</span>
              </td>
              <td style={td}>{a.ip_address}</td>
              <td
                style={{
                  ...td,
                  color: severityColor(a.severity)
                }}
              >
                {a.severity || "-"}
              </td>
              <td style={td}>{a.incident || "-"}</td>
              <td style={td}>{a.confidence || "-"}</td>
              <td style={td}>{a.risk_score ?? "-"}</td>
              <td style={td}>{a.kill_chain_stage || "-"}</td>
              <td style={td}>{getAnomalyScore(a)}</td>
              <td style={td}>{getDescription(a)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const th = { padding: "10px", textAlign: "left" };
const td = { padding: "10px" };


export default AlertsPage;
