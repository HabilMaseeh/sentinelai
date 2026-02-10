import { useEffect, useState } from "react";
import { fetchLogs } from "../services/api";

function LogsPage() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetchLogs().then(setLogs);
  }, []);

  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const getTime = (log) => {
    const value = log.event_time || log.timestamp || log.ingested_at;
    if (!value) return "-";
    return new Date(value).toLocaleString("en-US", {
      timeZone,
      hour12: true
    });
  };

  const nowLocal = new Date().toLocaleString("en-US", { timeZone, hour12: true });
  const nowUtc = new Date().toISOString().replace("T", " ").replace("Z", " UTC");

  return (
    <div style={{ padding: "20px" }}>
      <h1>Logs Explorer</h1>
      <div style={{ marginBottom: "10px", fontSize: "12px", color: "#94a3b8" }}>
        Browser TZ: {timeZone} | Local now: {nowLocal} | UTC now: {nowUtc}
      </div>

      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#1e293b" }}>
            <th style={th}>Time</th>
            <th style={th}>Event</th>
            <th style={th}>User</th>
            <th style={th}>IP</th>
            <th style={th}>Severity</th>
            <th style={th}>Message</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((l) => (
            <tr key={l._id} style={{ borderBottom: "1px solid #334155" }}>
              <td style={td}>{getTime(l)}</td>
              <td style={td}>{l.event_type}</td>
              <td style={td}>{l.username}</td>
              <td style={td}>{l.ip_address}</td>
              <td style={td}>{l.severity || "-"}</td>
              <td style={td}>{l.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const th = { padding: "10px" };
const td = { padding: "10px" };

export default LogsPage;
