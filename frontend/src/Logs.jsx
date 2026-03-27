import { useEffect, useState } from "react";

const BASE = "http://127.0.0.1:8080";

export default function Logs() {
  const [logs, setLogs] = useState([]);

  const fetchLogs = async () => {
    try {
      const res = await fetch(BASE + "/logs");
      const data = await res.json();
      setLogs(data.reverse());
    } catch (e) {
      console.error("Log fetch error:", e);
      setLogs([]);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div>
      <h2>📊 Attack Logs</h2>
      <button onClick={fetchLogs}>Refresh</button>

      <table border="1" cellPadding="6" style={{ marginTop: 10, width: "100%" }}>
        <thead>
          <tr>
            <th>#</th>
            <th>Status</th>
            <th>Attack Type</th>
            <th>Pattern</th>
            <th>Field</th>
            <th>Payload</th>
          </tr>
        </thead>

        <tbody>
          {logs.map((log, i) => {
            // ✅ CASE 1: attack logs
            if (log.findings && log.findings.length > 0) {
              return log.findings.map((f, j) => (
                <tr key={`${i}-${j}`}>
                  <td>{i + 1}</td>
                  <td style={{ color: "red" }}>BLOCKED</td>
                  <td>{f.attack_type}</td>
                  <td>{f.pattern}</td>
                  <td>{f.field}</td>
                  <td style={{ maxWidth: 300, wordWrap: "break-word" }}>
                    {log.raw_payload}
                  </td>
                </tr>
              ));
            }

            // ✅ CASE 2: passed logs
            return (
              <tr key={i}>
                <td>{i + 1}</td>
                <td style={{ color: "green" }}>PASSED</td>
                <td colSpan="3">—</td>
                <td>{log.path || "normal request"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}