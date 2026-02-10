import { useEffect, useState } from "react";
import AlertsPage from "./pages/AlertsPage";
import LogsPage from "./pages/LogsPage";
import IncidentsPage from "./pages/IncidentsPage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import AboutPage from "./pages/AboutPage";

function App() {
  const getInitialPage = () => {
    const hash = window.location.hash.replace("#", "");
    if (hash === "logs") return "logs";
    if (hash === "incidents") return "incidents";
    if (hash === "about") return "about";
    if (hash.startsWith("incident")) return "incident";
    return "alerts";
  };

  const [page, setPage] = useState(getInitialPage);

  useEffect(() => {
    const onHashChange = () => {
      setPage(getInitialPage());
    };

    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <div style={{ background: "#0f172a", minHeight: "100vh", minWidth: "100vw", color: "white" }}>
      <div style={{ padding: "10px", borderBottom: "1px solid #334155" }}>
        <button onClick={() => (window.location.hash = "alerts")}>Alerts</button>{" "}
        <button onClick={() => (window.location.hash = "incidents")}>Incidents</button>{" "}
        <button onClick={() => (window.location.hash = "logs")}>Logs</button>{" "}
        <button onClick={() => (window.location.hash = "about")}>About</button>
      </div>

      {page === "alerts" ? (
        <AlertsPage />
      ) : page === "incidents" ? (
        <IncidentsPage />
      ) : page === "incident" ? (
        <IncidentDetailPage />
      ) : page === "about" ? (
        <AboutPage />
      ) : (
        <LogsPage />
      )}

      <div style={{ borderTop: "1px solid #334155", padding: "12px 10px", color: "#94a3b8" }}>
        developed by Habil Maseeh
      </div>
    </div>
  );
}

export default App;
