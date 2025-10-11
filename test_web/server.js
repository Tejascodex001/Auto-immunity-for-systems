const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
const db = new sqlite3.Database("./database.db");
app.set('trust proxy', true);

// --- Logging Setup (no changes) ---
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logFile = path.join(logDir, "app.log");

function logEvent(eventType, message, req = null) {
  const timestamp = new Date().toISOString();
  const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : 'SYSTEM';
  const logMessage = `[${timestamp}] [${eventType.toUpperCase()}] ${message} from ${ip}\n`;
  fs.appendFile(logFile, logMessage, (err) => {
    if (err) console.error("Error writing to log file:", err);
  });
  console.log(logMessage.trim());
}

// --- DDoS Middleware (no changes) ---
const requestTracker = {};
const rateLimitMiddleware = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();
    if (!requestTracker[ip]) requestTracker[ip] = [];
    requestTracker[ip] = requestTracker[ip].filter(timestamp => now - timestamp < 60000);
    requestTracker[ip].push(now);
    if (requestTracker[ip].length > 50) {
        logEvent("CRITICAL", `Potential DDoS attack detected: ${requestTracker[ip].length} requests in 60s`, req);
    }
    next();
};
app.use(rateLimitMiddleware);
const loginAttemptTracker = {};

// --- Standard Middleware (no changes) ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// =====================================================================================
// --- DATABASE INITIALIZATION (MODIFIED) ---
// =====================================================================================
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`, (err) => {
    if (err) logEvent("ERROR", `DB init error: ${err.message}`);
    else logEvent("INFO", "Database initialized successfully");
  });
  
  // Ensure a default admin user exists with a PLAINTEXT password
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
      if (!row) {
          logEvent("INFO", "Default 'admin' user not found. Creating one.");
          db.run("INSERT INTO users (username, password) VALUES ('admin', 'adminpassword')");
      }
  });
});

// =====================================================================================
// --- SIGNUP ROUTE (MODIFIED) ---
// --- It no longer hashes the password. ---
// =====================================================================================
app.post("/signup", (req, res) => {
  const { username, password } = req.body;
  
  // Storing password in plaintext - insecure but simple for the demo
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password], function (err) {
    if (err) {
      logEvent("WARN", `Signup failed for user '${username}'`, req);
      return res.status(400).json({ message: "User already exists" });
    }
    logEvent("INFO", `New user signed up: ${username}`, req);
    res.json({ message: "Signup successful" });
  });
});

// =====================================================================================
// --- VULNERABLE LOGIN ROUTE (MODIFIED AND SIMPLIFIED) ---
// =====================================================================================
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // --- THE VULNERABILITY: Unsafe string concatenation ---
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  logEvent("QUERY", `Executing SQL query: ${query}`, req);

  // db.get() will only return the FIRST row that matches the query.
  db.get(query, (err, row) => {
    if (err) {
      logEvent("ERROR", `DB error on login: ${err.message}`, req);
      return res.status(500).json({ message: "Database error" });
    }
    
    // If the query returns ANY row (due to the injection), the login is successful.
    if (row) {
      delete loginAttemptTracker[ip]; // Reset brute force counter
      logEvent("INFO", `User logged in successfully (as ${row.username})`, req);
      res.json({ message: "Login successful" });
    } else {
      // Brute force tracking logic
      if (!loginAttemptTracker[ip]) loginAttemptTracker[ip] = 0;
      loginAttemptTracker[ip]++;
      logEvent("WARN", `Login failed for user: '${username}'`, req);
      if (loginAttemptTracker[ip] > 5) {
        logEvent("CRITICAL", `Brute force attack detected: ${loginAttemptTracker[ip]} failed attempts`, req);
      }
      res.status(400).json({ message: "Invalid credentials" });
    }
  });
});

// 404 Handler and Server Start (no changes)
app.use((req, res) => { /* ... */ });
const PORT = 3000;
app.listen(PORT, () => { /* ... */ });