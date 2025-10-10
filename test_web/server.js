const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");

const app = express();
const db = new sqlite3.Database("./database.db");

// Ensure logs directory exists
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}
const logFile = path.join(logDir, "app.log");

// --- Helper: Log function ---
function logEvent(eventType, message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${eventType.toUpperCase()}] ${message}\n`;
  fs.appendFile(logFile, logMessage, (err) => {
    if (err) console.error("Error writing to log file:", err);
  });
  console.log(logMessage.trim());
}

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Initialize DB
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) logEvent("ERROR", `DB init error: ${err.message}`);
    else logEvent("INFO", "Database initialized successfully");
  });
});

// Signup route
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function (err) {
      if (err) {
        logEvent("WARN", `Signup failed for user '${username}' (User may already exist)`);
        return res.status(400).json({ message: "User already exists" });
      }
      logEvent("INFO", `New user signed up: ${username}`);
      res.json({ message: "Signup successful" });
    }
  );
});

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) {
      logEvent("ERROR", `DB error during login for user '${username}': ${err.message}`);
      return res.status(500).json({ message: "Database error" });
    }
    if (!row) {
      logEvent("WARN", `Login failed — username not found: ${username}`);
      return res.status(400).json({ message: "Invalid username" });
    }

    const valid = await bcrypt.compare(password, row.password);
    if (!valid) {
      logEvent("WARN", `Login failed — incorrect password for user: ${username}`);
      return res.status(400).json({ message: "Invalid password" });
    }

    logEvent("INFO", `User logged in successfully: ${username}`);
    res.json({ message: "Login successful" });
  });
});

// Handle 404 (any other route)
app.use((req, res) => {
  logEvent("WARN", `404 Not Found: ${req.originalUrl}`);
  res.status(404).send("Page not found");
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  logEvent("INFO", `Server started on http://localhost:${PORT}`);
});
