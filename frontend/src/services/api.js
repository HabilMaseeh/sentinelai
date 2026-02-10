const BASE_URL = "http://127.0.0.1:8000/api";

export async function fetchAlerts(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE_URL}/alerts?${query}`);
  return res.json();
}

export async function fetchLogs(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE_URL}/logs?${query}`);
  return res.json();
}

export async function fetchIncidents(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE_URL}/incidents?${query}`);
  return res.json();
}

export async function fetchIncidentDetails(incidentKey) {
  const res = await fetch(`${BASE_URL}/incidents/${incidentKey}/details`);
  return res.json();
}

export function getIncidentReportUrl(incidentKey, format = "txt") {
  return `${BASE_URL}/incidents/${incidentKey}/report?format=${format}`;
}

export async function fetchMlStatus() {
  const res = await fetch(`${BASE_URL}/ml/status`);
  return res.json();
}
