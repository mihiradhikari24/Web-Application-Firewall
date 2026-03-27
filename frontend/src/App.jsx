import { useState } from "react";
import Playground from "./Playground";
import Logs from "./Logs";

export default function App() {
  const [page, setPage] = useState("playground");

  return (
    <div style={{ fontFamily: "monospace", padding: 20 }}>
      <h1>🛡️ WAF Dashboard</h1>

      <div style={{ marginBottom: 20 }}>
        <button onClick={() => setPage("playground")}>⚔️ Playground</button>
        <button onClick={() => setPage("logs")} style={{ marginLeft: 10 }}>
          📊 Logs
        </button>
      </div>

      {page === "playground" && <Playground />}
      {page === "logs" && <Logs />}
    </div>
  );
}