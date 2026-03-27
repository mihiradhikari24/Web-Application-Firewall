import { useState } from "react";

const BASE = "http://127.0.0.1:8080";

const attackGroups = {
  "✅ Legitimate Requests": [
    { name: "Normal Search", method: "GET", path: "/search?q=alice" },
    { name: "View Profile", method: "GET", path: "/profile?name=Alice" },
    { name: "View Comments", method: "GET", path: "/comments" },
    {
      name: "Normal Login",
      method: "POST",
      path: "/login",
      body: { username: "alice", password: "pass456" },
    },
    {
      name: "Add Comment",
      method: "POST",
      path: "/comment",
      body: { author: "Bob", body: "Nice post!" },
    },
  ],

  "SQL Injection": [
    { name: "OR 1=1", method: "GET", path: "/search?q=' OR 1=1--" },
    {
      name: "Login Bypass",
      method: "POST",
      path: "/login",
      body: { username: "admin'--", password: "x" },
    },
  ],

  XSS: [
    { name: "Script Tag", method: "GET", path: "/profile?name=<script>alert(1)</script>" },
    {
      name: "Stored XSS",
      method: "POST",
      path: "/comment",
      body: { author: "x", body: "<script>alert(1)</script>" },
    },
  ],

  "Path Traversal": [
    { name: "Basic", method: "GET", path: "/file?name=../../etc/passwd" },
  ],

  "Command Injection": [
    { name: "Subshell", method: "GET", path: "/search?q=alice$(whoami)" },
  ],
};

export default function Playground() {
  const [result, setResult] = useState(null);
  const [debug, setDebug] = useState("");

  const send = async (attack) => {
    try {
      setDebug(`➡️ ${attack.method} ${BASE}${attack.path}`);

      let res;

      if (attack.method === "GET") {
        res = await fetch(BASE + encodeURI(attack.path));
      } else {
        res = await fetch(BASE + attack.path, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(attack.body),
        });
      }

      const text = await res.text();

      setDebug((prev) => prev + `\n⬅️ Status: ${res.status}`);

      setResult({
        ...attack,
        status: res.status,
        response: text,
      });
    } catch (e) {
      setDebug("ERROR: " + e.message);
    }
  };

  return (
    <div>
      <h2>⚔️ Attack Playground</h2>

      {/* Attack Groups */}
      {Object.entries(attackGroups).map(([group, attacks]) => (
        <div key={group} style={{ marginBottom: 15 }}>
          <h3>{group}</h3>
          {attacks.map((a, i) => (
            <button key={i} onClick={() => send(a)} style={{ marginRight: 8 }}>
              {a.name}
            </button>
          ))}
        </div>
      ))}

      {/* Result */}
      {result && (
        <div style={{ marginTop: 20 }}>
          <h3>📤 Request</h3>
          <pre>
            {result.method} {result.path}
          </pre>

          <h3>📥 Result</h3>
          <p
            style={{
              fontWeight: "bold",
              color: result.status === 403 ? "red" : "green",
            }}
          >
            {result.status} {result.status === 403 ? "❌ BLOCKED" : "✅ PASSED"}
          </p>

          <h3>📄 Response</h3>
          <pre style={{ maxHeight: 200, overflow: "auto", background: "#eee" }}>
            {result.response}
          </pre>
        </div>
      )}

      {/* Debug */}
      <h3>🐞 Debug</h3>
      <pre style={{ background: "#111", color: "#0f0", padding: 10 }}>
        {debug}
      </pre>
    </div>
  );
}