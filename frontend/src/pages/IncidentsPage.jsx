import { useEffect, useState } from "react";
import { fetchIncidents, fetchIncidentDetails } from "../services/api";

function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [details, setDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    fetchIncidents().then(setIncidents);
  }, []);

  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const formatTime = (value) => {
    if (!value) return "-";
    return new Date(value).toLocaleString("en-US", {
      timeZone,
      hour12: true
    });
  };

  async function loadDetails(incidentKey) {
    setSelectedKey(incidentKey);
    setLoadingDetails(true);
    const data = await fetchIncidentDetails(incidentKey);
    setDetails(data);
    setLoadingDetails(false);
  }

  return (
    <div style={{ padding: "20px" }}>
      <h1>UEBA Incidents</h1>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#1e293b" }}>
            <th style={th}>Last Seen</th>
            <th style={th}>Incident</th>
            <th style={th}>IP</th>
            <th style={th}>Risk</th>
            <th style={th}>Risk (Decayed)</th>
            <th style={th}>Events</th>
            <th style={th}>Kill Chain</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((i) => (
            <tr
              key={i._id}
              style={{ borderBottom: "1px solid #334155", cursor: "pointer" }}
              onClick={() => {
                if (!i.incident_key) return;
                const url = `/#incident?key=${encodeURIComponent(i.incident_key)}`;
                window.open(url, "_blank", "noopener,noreferrer");
              }}
            >
              <td style={td}>{formatTime(i.last_seen || i.timestamp)}</td>
              <td style={td}>{i.incident || "-"}</td>
              <td style={td}>{i.ip_address}</td>
              <td style={td}>{i.risk_score ?? "-"}</td>
              <td style={td}>{i.risk_score_decayed ?? "-"}</td>
              <td style={td}>{i.event_count ?? "-"}</td>
              <td style={td}>{i.kill_chain_stage || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ marginTop: "20px" }}>
        <h2 style={{ fontSize: "18px", marginBottom: "8px" }}>
          Incident Detail
        </h2>
        {loadingDetails && <div>Loading…</div>}
        {!loadingDetails && !details && <div>Select an incident row.</div>}
        {!loadingDetails && details && (
          <div>
            <div style={{ marginBottom: "8px", color: "#94a3b8" }}>
              Key: {selectedKey}
            </div>
            <div style={{ marginBottom: "8px" }}>
              Summary: {details.summary || "-"}
            </div>

            <div style={{ marginBottom: "12px" }}>
              Counts: total={details.counts?.total ?? "-"}, failed=
              {details.counts?.failed ?? "-"}, invalid=
              {details.counts?.invalid ?? "-"}, success=
              {details.counts?.success ?? "-"}
            </div>

            <div style={{ marginBottom: "12px" }}>
              Graph Nodes:
              <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "6px" }}>
                <thead>
                  <tr style={{ background: "#1e293b" }}>
                    <th style={th}>ID</th>
                    <th style={th}>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {(details.graph?.nodes || []).map((n, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={td}>{n.id}</td>
                      <td style={td}>{n.type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ marginBottom: "12px" }}>
              Graph Edges:
              <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "6px" }}>
                <thead>
                  <tr style={{ background: "#1e293b" }}>
                    <th style={th}>From</th>
                    <th style={th}>To</th>
                    <th style={th}>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {(details.graph?.edges || []).map((e, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={td}>{e.from}</td>
                      <td style={td}>{e.to}</td>
                      <td style={td}>{e.type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div>
              Timeline:
              <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "6px" }}>
                <thead>
                  <tr style={{ background: "#1e293b" }}>
                    <th style={th}>Time</th>
                    <th style={th}>Event</th>
                    <th style={th}>User</th>
                    <th style={th}>IP</th>
                    <th style={th}>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {(details.timeline || []).map((t, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #334155" }}>
                      <td style={td}>{formatTime(t.time)}</td>
                      <td style={td}>{t.event_type}</td>
                      <td style={td}>{t.username || "-"}</td>
                      <td style={td}>{t.ip_address || "-"}</td>
                      <td style={td}>{t.message || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const th = { padding: "10px", textAlign: "left" };
const td = { padding: "10px" };

export default IncidentsPage;
