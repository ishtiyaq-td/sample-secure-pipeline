// app.js  —  intentionally vulnerable Node.js/Express app
// PURPOSE: trigger every security check in the CI/CD pipeline
// DO NOT deploy to production

const express = require("express");
const mysql = require("mysql2");
const serialize = require("node-serialize");
const exec = require("child_process").exec;
const fs = require("fs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────
// ISSUE 1 — Hardcoded secrets (triggers Gitleaks + SonarQube)
// ─────────────────────────────────────────────
const DB_PASSWORD = "SuperSecret123!";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const JWT_SECRET = "mysecret";

// After — clearly fake, won't trigger push protection
const STRIPE_KEY = "sk_live_FAKE_KEY_FOR_DEMO_ONLY";

// ─────────────────────────────────────────────
// ISSUE 2 — SQL Injection (triggers CodeQL + SonarQube)
// ─────────────────────────────────────────────
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "users_db",
});

app.get("/user", (req, res) => {
  const username = req.query.username;

  // VULN: raw user input concatenated directly into SQL query
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// ─────────────────────────────────────────────
// ISSUE 3 — Command Injection (triggers CodeQL + SonarQube)
// ─────────────────────────────────────────────
app.post("/ping", (req, res) => {
  const host = req.body.host;

  // VULN: user input passed directly to shell
  exec("ping -c 1 " + host, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// ─────────────────────────────────────────────
// ISSUE 4 — Remote Code Execution via deserialization
//           (triggers CodeQL + SonarQube)
// ─────────────────────────────────────────────
app.post("/import", (req, res) => {
  const data = req.body.data;

  // VULN: deserializing untrusted user input — classic RCE vector
  const obj = serialize.unserialize(data);
  res.json(obj);
});

// ─────────────────────────────────────────────
// ISSUE 5 — Path Traversal (triggers CodeQL + Trivy config scan)
// ─────────────────────────────────────────────
app.get("/file", (req, res) => {
  const filename = req.query.name;

  // VULN: no path sanitisation — attacker can read ../../etc/passwd
  const filePath = "./uploads/" + filename;
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(404).send("Not found");
    res.send(data);
  });
});

// ─────────────────────────────────────────────
// ISSUE 6 — Broken authentication / weak JWT
//           (triggers SonarQube + CodeQL)
// ─────────────────────────────────────────────
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // VULN: no real credential validation, just checks non-empty
  if (username && password) {
    // VULN: weak secret, algorithm not specified (defaults to HS256 with no validation)
    const token = jwt.sign({ user: username, role: "admin" }, JWT_SECRET);
    res.json({ token });
  } else {
    res.status(401).send("Unauthorized");
  }
});

app.get("/admin", (req, res) => {
  const token = req.headers.authorization;

  // VULN: algorithm not verified — susceptible to "alg: none" attack
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["none", "HS256"] });
    res.json({ message: "Welcome admin", user: decoded });
  } catch {
    res.status(403).send("Forbidden");
  }
});

// ─────────────────────────────────────────────
// ISSUE 7 — Weak cryptography (triggers SonarQube + CodeQL)
// ─────────────────────────────────────────────
app.post("/hash-password", (req, res) => {
  const { password } = req.body;

  // VULN: MD5 is cryptographically broken — should use bcrypt/argon2
  const hashed = crypto.createHash("md5").update(password).digest("hex");
  res.json({ hash: hashed });
});

// ─────────────────────────────────────────────
// ISSUE 8 — XSS via reflected user input (triggers ZAP + CodeQL)
// ─────────────────────────────────────────────
app.get("/search", (req, res) => {
  const term = req.query.q;

  // VULN: user input rendered directly into HTML without encoding
  res.send(`<html><body><h1>Results for: ${term}</h1></body></html>`);
});

// ─────────────────────────────────────────────
// ISSUE 9 — Sensitive data in logs (triggers SonarQube)
// ─────────────────────────────────────────────
app.post("/payment", (req, res) => {
  const { cardNumber, cvv, amount } = req.body;

  // VULN: PII / payment card data written to application logs
  console.log(`Processing payment: card=${cardNumber} cvv=${cvv} amount=${amount}`);
  console.log(`Using Stripe key: ${STRIPE_KEY}`);

  res.json({ status: "processed" });
});

// ─────────────────────────────────────────────
// ISSUE 10 — SSRF — Server-Side Request Forgery (triggers ZAP + CodeQL)
// ─────────────────────────────────────────────
const http = require("http");

app.get("/fetch", (req, res) => {
  const url = req.query.url;

  // VULN: no URL allowlist — attacker can hit internal metadata endpoints
  // e.g. http://169.254.169.254/latest/meta-data/
  http.get(url, (response) => {
    let data = "";
    response.on("data", (chunk) => (data += chunk));
    response.on("end", () => res.send(data));
  });
});

// ─────────────────────────────────────────────
// ISSUE 11 — Missing rate limiting + no security headers
//            (triggers ZAP DAST scan)
// ─────────────────────────────────────────────

// No helmet.js — missing X-Frame-Options, CSP, HSTS, X-Content-Type-Options
// No express-rate-limit — /login endpoint is brute-forceable

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

module.exports = app;
