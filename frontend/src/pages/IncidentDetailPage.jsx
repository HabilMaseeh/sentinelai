import { useEffect, useState } from "react";
import { fetchIncidentDetails, getIncidentReportUrl } from "../services/api";

function IncidentDetailPage() {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(false);

  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const formatTime = (value) => {
    if (!value) return "-";
    return new Date(value).toLocaleString("en-US", {
      timeZone,
      hour12: true
    });
  };

  useEffect(() => {
    const hash = window.location.hash.replace("#", "");
    const match = hash.match(/incident\?key=(.+)$/);
    const key = match ? decodeURIComponent(match[1]) : "";
    if (!key) return;

    setLoading(true);
    fetchIncidentDetails(key).then((data) => {
      setDetails(data);
      setLoading(false);
    });
  }, []);

  const reportUrl = details ? getIncidentReportUrl(details.incident?.incident_key || "", "txt") : "";
  const reportHtmlUrl = details ? getIncidentReportUrl(details.incident?.incident_key || "", "html") : "";

  return (
    <div style={{ padding: "20px" }}>
      <h1>Incident Detail</h1>
      {loading && <div>Loading…</div>}
      {!loading && !details && <div>No incident key provided.</div>}
      {!loading && details && (
        <div>
          <div style={{ marginBottom: "8px", color: "#94a3b8" }}>
            Summary: {details.summary || "-"}
          </div>

          <div style={{ marginBottom: "12px" }}>
            Counts: total={details.counts?.total ?? "-"}, failed=
            {details.counts?.failed ?? "-"}, invalid=
            {details.counts?.invalid ?? "-"}, success=
            {details.counts?.success ?? "-"}
          </div>

          <div style={{ marginBottom: "12px" }}>
            Enrichment: IP={details.enrichment?.ip ?? "-"}, private=
            {String(details.enrichment?.is_private ?? "-")}, reserved=
            {String(details.enrichment?.is_reserved ?? "-")}, global=
            {String(details.enrichment?.is_global ?? "-")}
          </div>
          <div style={{ marginBottom: "12px" }}>
            Threat Intel: {details.threat_intel?.status || "unknown"}
          </div>
          <div style={{ marginBottom: "12px" }}>
            Recommendations:
            <ul style={{ marginTop: "6px", paddingLeft: "18px" }}>
              {(details.recommendations || []).map((r, idx) => (
                <li key={idx}>{r}</li>
              ))}
            </ul>
          </div>
          <div style={{ marginBottom: "12px" }}>
            Kill Chain:
            <div style={{ display: "flex", gap: "6px", marginTop: "6px", flexWrap: "wrap" }}>
              {(details.kill_chain_all || []).map((stage, idx) => (
                <span
                  key={idx}
                  style={{
                    padding: "2px 8px",
                    borderRadius: "999px",
                    fontSize: "11px",
                    border: "1px solid #334155",
                    background: stage === details.kill_chain_stage ? "#1e293b" : "transparent",
                    color: stage === details.kill_chain_stage ? "#e2e8f0" : "#94a3b8"
                  }}
                >
                  {stage}
                </span>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: "12px" }}>
            <a href={reportUrl} download>Download Report (TXT)</a>{" "}
            <a href={reportHtmlUrl} download>Download Report (HTML)</a>
          </div>

            <div style={{ marginBottom: "12px" }}>
              Graph (rendered):
              {(() => {
                const nodes = details.graph?.nodes || [];
                const edges = details.graph?.edges || [];
                const width = 520;
                const height = 220;
                const cx = width / 2;
                const cy = height / 2;
                const r = 70;
                const pos = new Map();

                nodes.forEach((n, i) => {
                  const angle = (2 * Math.PI * i) / Math.max(1, nodes.length);
                  pos.set(n.id, {
                    x: cx + r * Math.cos(angle),
                    y: cy + r * Math.sin(angle)
                  });
                });

                return (
                  <svg
                    width={width}
                    height={height}
                    style={{ display: "block", marginTop: "6px", background: "#0b1220", border: "1px solid #1e293b" }}
                  >
                    {edges.map((e, idx) => {
                      const from = pos.get(e.from);
                      const to = pos.get(e.to);
                      if (!from || !to) return null;
                      return (
                        <line
                          key={idx}
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          stroke="#64748b"
                        />
                      );
                    })}
                    {nodes.map((n, idx) => {
                      const p = pos.get(n.id);
                      if (!p) return null;
                      return (
                        <g key={idx}>
                          <circle cx={p.x} cy={p.y} r="18" fill="#1e293b" stroke="#94a3b8" />
                          <text x={p.x} y={p.y + 4} textAnchor="middle" fill="#e2e8f0" fontSize="10">
                            {n.type}
                          </text>
                          <text x={p.x} y={p.y + 26} textAnchor="middle" fill="#94a3b8" fontSize="9">
                            {n.id}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                );
              })()}
              Nodes/Edges tables below for precision:
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
  );
}

const th = { padding: "10px", textAlign: "left" };
const td = { padding: "10px" };

export default IncidentDetailPage;
